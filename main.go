package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	hclog "github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

func main() {
	var kubernetesAuthRole string
	var serviceAccountTokenPath string
	var gcpServiceAccountKeyTTL string
	var bucket string

	flag.StringVar(&kubernetesAuthRole, "kubernetes-auth-role", "", "The role name of the Kubernetes auth.")
	flag.StringVar(&serviceAccountTokenPath, "service-account-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "The path of application's Kubernetes service account token.")
	flag.StringVar(&gcpServiceAccountKeyTTL, "ttl", "24h", "Time to live (TTL) for service account key.")
	flag.StringVar(&bucket, "bucket", "", "The bucket name of Google Cloud Storage(GCS).")

	flag.Parse()
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "vault-gcp-sakey-gen",
		Level: hclog.LevelFromString("INFO"),
	})

	logger.Info("Starting generator")

	now := time.Now()
	config := vault.DefaultConfig()
	ctx := context.Background()
	client, err := vault.NewClient(config)
	if err != nil {
		logger.Error("Unable to initialize Vault client", err)
		os.Exit(1)
	}
	k8sAuth, err := auth.NewKubernetesAuth(
		kubernetesAuthRole,
		auth.WithServiceAccountTokenPath(serviceAccountTokenPath),
	)
	if err != nil {
		logger.Error("Unable to initialize Kubernetes auth method", err)
		os.Exit(1)
	}

	authInfo, err := client.Auth().Login(ctx, k8sAuth)
	if err != nil {
		logger.Error("Unable to log in with Kubernetes auth", err)
		os.Exit(1)
	}
	if authInfo == nil {
		logger.Error("No auth info was returned after login")
		os.Exit(1)
	}

	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		logger.Error("Unable to list mounts", err)
		os.Exit(1)
	}
	mountPaths := mountOutputs(mounts).filterByType("gcp").keys()
	if len(mountPaths) == 0 {
		logger.Warn("No gcp mount was enabled, so skip the operation")
		return
	}

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.Error("Unable to initialize GCS client", err)
		os.Exit(1)
	}

	generateSecrets := func(mountPath string) error {
		path := fmt.Sprintf("%s%s", mountPath, "static-accounts") // The mountPath includes / at the suffix, so it is supposed to be like "gcp/static-accounts".
		secret, err := client.Logical().ListWithContext(ctx, path)
		if err != nil {
			logger.Error("Unable to list gcp static accounts", err)
			os.Exit(1)
		}
		serviceAccounts, ok := extractListData(secret)
		if len(serviceAccounts) == 0 || !ok {
			logger.Warn(fmt.Sprintf("No static account exists in the path, %s", path))
			return nil
		}
		var wg sync.WaitGroup
		for _, account := range serviceAccounts {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				path = fmt.Sprintf("%s%s/%s/%s", mountPath, "static-account", name, "key")
				req := map[string][]string{"ttl": {gcpServiceAccountKeyTTL}}
				secret, err := client.Logical().ReadWithDataWithContext(ctx, path, req)
				if err != nil && strings.Contains(err.Error(), "Precondition check failed.") {
					logger.Error(fmt.Sprintf("There is a default limit of 10 keys per Service Account, please revise the ttl and the interval of this job, %s", path), err)
					os.Exit(1)
				}
				if err != nil {
					logger.Error(fmt.Sprintf("Unable to read data, %s", path), err)
					os.Exit(1)
				}
				if secret == nil || secret.Data == nil {
					logger.Error(fmt.Sprintf("No value found at %s", path))
					os.Exit(1)
				}

				pkd, ok := secret.Data["private_key_data"]
				if !ok {
					logger.Error(fmt.Sprintf("No private key data found"))
					os.Exit(1)
				}

				path = fmt.Sprintf("%s%s/%s", mountPath, name, now.Format(time.RFC3339))
				if strings.Contains(mountPath, "gcp") {
					path = strings.Replace(path, "gcp/", "", 1)
				}
				w := gcsClient.Bucket(bucket).Object(path).NewWriter(ctx)
				if _, err := w.Write([]byte(pkd.(string))); err != nil {
					logger.Error("Unable to create a file in the bucket", err)
					os.Exit(1)
				}
				if err := w.Close(); err != nil {
					logger.Error("Unable to write the data", err)
					os.Exit(1)
				}
			}(account)
		}
		wg.Wait()
		return nil
	}

	var wg sync.WaitGroup
	for _, path := range mountPaths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := retry(generateSecrets, path, 3); err != nil {
				logger.Error("Unable to generate secrets in the path", path)
			}
		}()
	}

	wg.Wait()
	logger.Info("Completed GCP static account key generation")

}

func retry(f func(p string) error, args string, attempts int) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err := f(args); err == nil {
			return nil
		}
	}
	return err
}

type mountOutputs map[string]*vault.MountOutput

func (m mountOutputs) filterByType(typ string) mountOutputs {
	resp := make(mountOutputs, len(m))
	for k, v := range m {
		if v.Type != typ {
			continue
		}
		resp[k] = v
	}
	return resp
}

func (m mountOutputs) keys() []string {
	resp := make([]string, 0, len(m))
	for k, _ := range m {
		resp = append(resp, k)
	}
	return resp
}

func extractListData(secret *vault.Secret) ([]string, bool) {
	if secret == nil || secret.Data == nil {
		return nil, false
	}

	k, ok := secret.Data["keys"]
	if !ok || k == nil {
		return nil, false
	}

	var ret []string
	for _, v := range k.([]interface{}) {
		ret = append(ret, v.(string))
	}
	return ret, true
}
