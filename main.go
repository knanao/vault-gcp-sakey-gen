package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"slices"
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
	var target string
	var force bool

	flag.StringVar(&kubernetesAuthRole, "kubernetes-auth-role", "", "The role name of the Kubernetes auth.")
	flag.StringVar(&serviceAccountTokenPath, "service-account-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "The path of application's Kubernetes service account token.")
	flag.StringVar(&gcpServiceAccountKeyTTL, "ttl", "24h", "Time to live (TTL) for service account key.")
	flag.StringVar(&bucket, "bucket", "", "The bucket name of Google Cloud Storage(GCS).")
	flag.StringVar(&target, "target", "", "The target mount paths of the GCP secret engine must include a trailing /. e.g. -filter=gcp/,gcp/dev/")
	flag.BoolVar(&force, "force", false, "By default, the key file is named with a timestamp. If this flag is enabled, the name of the static accounts is used instead, and the file is overridden each time.")
	flag.Parse()

	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "vault-gcp-sakey-gen",
		Level: hclog.LevelFromString("INFO"),
	})
	logger.Info("Starting generator")

	var (
		now         = time.Now()
		config      = vault.DefaultConfig()
		targetPaths = strings.Split(target, ",")
		ctx         = context.Background()

		client *vault.Client
		err    error
	)
	{
		client, err = vault.NewClient(config)
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
	}

	gcsClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.Error("Unable to initialize GCS client", err)
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
	if len(targetPaths) != 0 {
		ts := make([]string, 0, len(targetPaths))
		for _, t := range targetPaths {
			if slices.Contains(mountPaths, t) {
				ts = append(ts, t)
			}
		}
		mountPaths = ts
	}

	generateSecrets := func(mountPath string) error {
		listStaticAccounts := fmt.Sprintf("%s%s", mountPath, "static-accounts") // The mountPath includes / at the suffix, so it is supposed to be like "gcp/static-accounts".
		list, err := client.Logical().ListWithContext(ctx, listStaticAccounts)
		if err != nil {
			logger.Error("Unable to list gcp static accounts", err)
			os.Exit(1)
		}
		serviceAccounts, ok := extractListData(list)
		if len(serviceAccounts) == 0 || !ok {
			logger.Warn(fmt.Sprintf("No static account exists in the path, %s", listStaticAccounts))
			return nil
		}

		var wg sync.WaitGroup
		for _, account := range serviceAccounts {
			wg.Add(1)
			go func(name string) {
				defer wg.Done()

				generateKey := fmt.Sprintf("%s%s/%s/%s", mountPath, "static-account", name, "key")
				req := map[string][]string{"ttl": {gcpServiceAccountKeyTTL}}
				secret, err := client.Logical().ReadWithDataWithContext(ctx, generateKey, req)
				if err != nil && strings.Contains(err.Error(), "Precondition check failed.") {
					logger.Error(fmt.Sprintf("There is a default limit of 10 keys per Service Account, please revise the ttl and the interval of this job, %s", generateKey), err)
					os.Exit(1)
				}
				if err != nil {
					logger.Error(fmt.Sprintf("Unable to read data, %s", generateKey), err)
					os.Exit(1)
				}
				if secret == nil || secret.Data == nil {
					logger.Error(fmt.Sprintf("No value found at %s", generateKey))
					os.Exit(1)
				}

				pkd, ok := secret.Data["private_key_data"]
				if !ok {
					logger.Error("No private key data found")
					os.Exit(1)
				}

				lookup, err := client.Sys().Lookup(secret.LeaseID)
				if err != nil {
					logger.Error(fmt.Sprintf("Unable to lookup the lease, %s", secret.LeaseID), err)
					os.Exit(1)
				}
				if lookup == nil || lookup.Data == nil {
					logger.Error(fmt.Sprintf("No lease found, %s", secret.LeaseID))
					os.Exit(1)
				}

				var (
					issueTime  string
					expireTime string
				)
				if v, ok := lookup.Data["issue_time"]; ok {
					if t, err := time.Parse(time.RFC3339, v.(string)); err == nil {
						issueTime = t.Local().Format(time.RFC3339)
					}
				}
				if v, ok := lookup.Data["expire_time"]; ok {
					if t, err := time.Parse(time.RFC3339, v.(string)); err == nil {
						expireTime = t.Local().Format(time.RFC3339)
					}
				}

				file := fmt.Sprintf("%s%s", mountPath, name)
				if !force {
					file = fmt.Sprintf("%s/%s", file, now.Format(time.RFC3339))
				}
				if strings.Contains(mountPath, "gcp") {
					file = strings.Replace(file, "gcp/", "", 1)
				}

				w := gcsClient.Bucket(bucket).Object(file).NewWriter(ctx)
				w.ObjectAttrs.Metadata = map[string]string{
					"issue_time":  issueTime,
					"expire_time": expireTime,
				}
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
