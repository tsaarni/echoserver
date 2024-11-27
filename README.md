# Test echoserver

This is a simple HTTP server that listens on incoming requests and echoes back information about the request.

It is inspired by the [echoserver](https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/images/echoserver) from the [ingress-controller-conformance](https://github.com/kubernetes-sigs/ingress-controller-conformance) project.

## Usage

### Environment Variables

| Variable        | Description                          | Default                                                   |
|-----------------|--------------------------------------|-----------------------------------------------------------|
| `PORT`          | Port for HTTP server                 | `8080` or `8443` if `TLS_CERT_FILE` and `TLS_KEY_FILE` are set |
| `TLS_CERT_FILE` | Path to TLS certificate file         |                                                           |
| `TLS_KEY_FILE`  | Path to TLS key file                 |                                                           |
| `ENV_*`         | Environment variables to be echoed   |                                                           |
