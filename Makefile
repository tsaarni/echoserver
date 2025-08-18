.PHONY: all lint lint-go lint-js lint-html clean container generate-test-certs run

all:
	CGO_ENABLED=0 go build .

container:
	docker build -t ghcr.io/tsaarni/tsaarni/echoserver:latest .

clean:
	@rm -f echoserver

lint: lint-go lint-js lint-html

lint-go:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0 run

lint-js:
	npx eslint .

lint-html:
	npx htmlhint "**/*.html"

generate-test-certs:
	@mkdir -p testdata/certs
	go run github.com/tsaarni/certyaml/cmd/certyaml@v0.10.0 -d testdata/certs testdata/certs.yaml

run: generate-test-certs
	go run . -live -tls-cert-file testdata/certs/echoserver.pem -tls-key-file testdata/certs/echoserver-key.pem
