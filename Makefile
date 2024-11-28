.PHONY: all lint lint-go lint-js lint-html clean

all:
	CGO_ENABLED=0 go build

container:
	docker build -t ghcr.io/tsaarni/tsaarni/echoserver:latest .

clean:
	@rm -f echoserver

lint: lint-go lint-js lint-html

lint-go:
	go run github.com/golangci/golangci-lint/cmd/golangci-lint run

lint-js:
	npx eslint .

lint-html:
	npx htmlhint "**/*.html"
