.PHONY: all lint lint-go lint-js lint-html clean container generate-test-certs run

all: generate-proto
	CGO_ENABLED=0 go build .

container:
	docker build -t ghcr.io/tsaarni/echoserver:latest .

clean:
	@rm -f echoserver

lint: lint-go lint-js lint-html

lint-go:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.1 run

lint-js:
	npx eslint .

lint-html:
	npx htmlhint "**/*.html"

generate-test-certs:
	@mkdir -p testdata/certs
	go run github.com/tsaarni/certyaml/cmd/certyaml@v0.10.0 -d testdata/certs testdata/certs.yaml

generate-proto: proto/echo.pb.go proto/echo_grpc.pb.go

proto/echo.pb.go proto/echo_grpc.pb.go: proto/echo.proto
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/echo.proto

run: generate-test-certs generate-proto
	go run . -http-addr 127.0.0.1:8080 -https-addr 127.0.0.1:8443 -live -tls-cert-file testdata/certs/echoserver.pem -tls-key-file testdata/certs/echoserver-key.pem
