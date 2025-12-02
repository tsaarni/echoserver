.PHONY: all lint lint-go lint-js lint-html clean container generate-test-certs run test generate-proto

all: generate-proto ## Build the echoserver binary.
	CGO_ENABLED=0 go build .

container: ## Create container image.
	docker buildx build -t ghcr.io/tsaarni/echoserver:latest .

clean: ## Clean up build artifacts.
	@rm -f echoserver coverage-e2e.out coverage-e2e.html test/testdata/certs/*

lint: lint-go lint-js lint-html  ## Run all linters.

lint-go: ## Run golangci-lint.
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1 run

lint-js: ## Run ESLint.
	npx eslint .

lint-html: ## Run HTMLHint.
	npx htmlhint "apps/*.html"

generate-test-certs: ## Generate test certificates.
	@mkdir -p test/testdata/certs
	go run github.com/tsaarni/certyaml/cmd/certyaml@v0.10.0 -d test/testdata/certs test/testdata/certs.yaml

generate-proto: ## Generate gRPC Go code from proto files.
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/echo.proto

run: generate-test-certs  ## Run the server.
	go run . -http-addr 127.0.0.1:8080 -https-addr 127.0.0.1:8443 -live -tls-cert-file test/testdata/certs/echoserver.pem -tls-key-file test/testdata/certs/echoserver-key.pem

test: generate-test-certs ## Run end-to-end tests.
	# Limit coverage to the main server package to avoid noise from generated proto code
	go test -v -tags e2e -coverpkg=github.com/tsaarni/echoserver/server -coverprofile=coverage-e2e.out ./test/...
	go tool cover -func=coverage-e2e.out
	@echo "HTML coverage report: coverage-e2e.html"
	@go tool cover -html=coverage-e2e.out -o coverage-e2e.html

help: ## Show this help.
	@awk '/^[a-zA-Z_-]+:.*## / { sub(/:.*## /, "\t"); split($$0,a, "\t"); printf "\033[36m%-30s\033[0m %s\n", a[1], a[2] }' $(MAKEFILE_LIST)
