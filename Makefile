BUILD_VERSION=v0.1.0
REPOSITORY=ghcr.io/knanao/vault-gcp-sakey-gen

.PHONY: build
build:
	docker build --platform linux/amd64 -t ${REPOSITORY}:${BUILD_VERSION} -t ${REPOSITORY}:latest .

.PHONY: push
push: build
push:
	docker push ${REPOSITORY}:${BUILD_VERSION}
	docker push ${REPOSITORY}:latest

.PHONY: run
run: VAULT_ADDR ?=
run: K8S_AUTH_ROLE ?=
run: BATCH_TOKEN_ROLE ?=
run: GCS_BUCKET ?=
run:
	docker run -e VAULT_ADDR=${VAULT_ADDR} ${REPOSITORY}:${BUILD_VERSION} --kubernetes-auth-role=${K8S_AUTH_ROLE} --batchTokenRole=${BATCH_TOKEN_ROLE} --bucket=${GCS_BUCKET}
