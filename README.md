# Echoserver

This is a simple HTTP server that listens on incoming requests and echoes back information about the request.
It is inspired by the [echoserver](https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/images/echoserver) from the [ingress-controller-conformance](https://github.com/kubernetes-sigs/ingress-controller-conformance) project.

The server will respond to the following paths:

- `/*` - Returns request details in JSON format, including headers and TLS information.
- `/apps/health` - A `200 OK` status is returned, indicating the server is operational.
- `/apps/status/{code}` - Returns the specified HTTP status code. Optionally, a JSON object (e.g., `{ "Location": "http://localhost/bar" }`) can be provided in the body to include additional HTTP headers in the response.
- `/apps/fetch.html` - A JavaScript application that allows HTTP requests to be made using various methods and the responses to be viewed.
- `/apps/form.html` - HTML form that allows data to be submitted using `POST` and `GET` methods.
- `/apps/oauth.html` - OAuth2-aware JavaScript application, enabling authentication with the server using the Authorization Code flow and making authenticated requests.

## Deploying

Echoserver is available as a container image

```
ghcr.io/tsaarni/tsaarni/echoserver:latest
```

## Usage

### Environment Variables

| Variable        | Description                                                                                                           | Default |
| --------------- | --------------------------------------------------------------------------------------------------------------------- | ------- |
| `HTTP_PORT`     | Port for HTTP server                                                                                                  | `8080`  |
| `HTTPS_PORT`    | Port for HTTPS server                                                                                                 | `8443`  |
| `TLS_CERT_FILE` | Path to TLS certificate file                                                                                          |         |
| `TLS_KEY_FILE`  | Path to TLS key file                                                                                                  |         |
| `ENV_*`         | List of environment variables to be included in the `env` field of the JSON response and accessible in HTML templates |         |

Environment variables that are used by the HTML pages are:

| Variable       | Description            | Default   |
| -------------- | ---------------------- | --------- |
| `ENV_HOSTNAME` | Hostname of the server | localhost |

### Command Line Arguments

| Argument | Description                                                                     | Default |
| -------- | ------------------------------------------------------------------------------- | ------- |
| `-live`  | Serve static files directly from the filesystem instead of using bundled files. | `false` |

## Development

To build and run the echoserver locally, use the following commands:

```sh
make build
./echoserver
```

To serve HTML files from the filesystem instead of using bundled files, use the following command:

```sh
./echoserver -live
```

To build the container image, use the following command:

```sh
make container
```

To lint the code, use the following command:

```sh
make lint
```
