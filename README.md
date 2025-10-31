# Echoserver

Echoserver is a simple HTTP server that listens on incoming requests and echoes back
information about the request. It is inspired by the
[echoserver](https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/images/echoserver)
from the
[ingress-controller-conformance](https://github.com/kubernetes-sigs/ingress-controller-conformance)
project. Additionally, the server can be used to test authentication and
authorization features in ingress controllers by providing browser based clients that make
requests to the echoserver.
See also [echoclient](https://github.com/tsaarni/echoclient) project, a programmable HTTP load testing library.

## Usage

To run the server locally it can be installed or run directly using following commands:

```sh
go install github.com/tsaarni/echoserver@latest # Install the binary.
go run github.com/tsaarni/echoserver@latest     # Run the server without installing.
```

Echoserver is also available as a container image:

```
ghcr.io/tsaarni/echoserver:latest
```

Echoserver can be configured either using command line arguments or environment variables.
Command line arguments take precedence over environment variables.
Following table lists the available configuration options:

| Command line     | Variable        | Description                                                                                                            | Default  |
| ---------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------- | -------- |
| `-http-addr`     | `HTTP_ADDR`     | Address to bind the HTTP server socket.                                                                                | `:8080`  |
| `-https-addr`    | `HTTPS_ADDR`    | Address to bind the HTTPS server socket.                                                                               | `:8443`  |
| `-tls-cert-file` | `TLS_CERT_FILE` | Path to TLS certificate file.                                                                                          |          |
| `-tls-key-file`  | `TLS_KEY_FILE`  | Path to TLS key file.                                                                                                  |          |
|                  | `ENV_*`         | List of environment variables to be included in the `env` field of the JSON response and accessible in HTML templates. |          |
| `-live`          |                 | Serve static files directly from the `./apps` directory instead of using bundled files in the binary.                  | `false`  |
|                  | `SSLKEYLOGFILE` | Path to write the TLS master secret log file to. See [Wireshark documentation][1] for more information.                |          |
| `-log-level`     | `LOG_LEVEL`     | Log level. Possible values are `debug`, `info`, `warn`, and `error`.                                                   | `debug`  |

The certificate and key files will be loaded from the filesystem every time a request is made to the server, so it is possible to update the certificate and
key files without restarting the server.

### API

Example commands in the descriptions are given using the [HTTPie](https://httpie.io/) tool.

#### <code>/*</code> - Returns request details in JSON format.

<details>

##### Responses

| Status | Description                     |
| ------ | ------------------------------- |
| 200 OK | Request details in JSON format. |

Following fields is included in the response:

- `content_length`: Length of the request body.
- `env`: Environment variables provided in the configuration.
- `headers`: Request headers.
- `host`: Host and port of the server.
- `method`: HTTP method of the request.
- `url`: Request URL.
- `proto`: HTTP protocol version.
- `remote`: Remote address of the client.
- `env`: Variables from the process environment that match the `ENV_*` prefix.
- `tls`: TLS details if the request was made over HTTPS.
  - `alpn_negotiated_protocol`: Application Layer Protocol Negotiation protocol.
  - `cipher_suite`: Cipher suite used in the connection.
  - `peer_certificates`: Peer certificates in PEM format if the client provided a certificate.
  - `peer_certificates_decoded`: Decoded peer certificate details if the client provided a certificate.
    - `subject`: Subject of the certificate.
    - `issuer`: Issuer of the certificate.
    - `serial_number`: Serial number of the certificate.
    - `not_before`: Not before date of the certificate.
    - `not_after`: Not after date of the certificate.
  - `version`: TLS version.
- `query`: Query parameters of the request if the URL contains a query string.
- `form`: Form parameters of the request body, if the content type is `application/x-www-form-urlencoded`.
- `cookies`: Cookies in the request if the request had a `Cookie` header.
- `body`: Request body.
- `jwt`: JWT claims if the request had JWT in the `Authorization` header.
  - `header`: JWT header.
  - `claims`: JWT claims.
    - If the `claims` field contains `iat` or `exp` claims, they are converted to human-readable format and added as `iat_date` and `exp_date` fields (these fields are added by the server and are not part of the original token).
- `basic_auth`: Basic authentication credentials if the request had `Authorization` header with `Basic` scheme.
  - `username`: Username.
  - `password`: Password.

##### Example

```console
$ http --cert testdata/certs/client.pem --cert-key testdata/certs/client-key.pem --verify testdata/certs/ca.pem https://localhost:8443/foobar
```

```json
{
    "content_length": 0,
    "headers": {
        "Accept": [
            "*/*"
        ],
        "Accept-Encoding": [
            "gzip, deflate"
        ],
        "Connection": [
            "keep-alive"
        ],
        "User-Agent": [
            "HTTPie/3.2.4"
        ]
    },
    "host": "localhost:8443",
    "method": "GET",
    "proto": "HTTP/1.1",
    "remote": "[::1]:57961",
    "tls": {
        "alpn_negotiated_protocol": "http/1.1",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "peer_certificates": "-----BEGIN CERTIFICATE-----\nMIIBRTCB7aADAgECAggYXbRNl099CjAKBggqhkjOPQQDAjANMQswCQYDVQQDEwJj\nYTAeFw0yNTA4MjEwNjI3NTVaFw0yNjA4MjEwNjI3NTVaMBExDzANBgNVBAMTBmNs\naWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPhO4qIu71Cm5Ox5U5Pb6Og2\n4EMh/lWU4+OGDBkHIRXtyKTZCXzH5a1vQ0TO1jq6sjShZR8ihDYXRuPfcNVefj6j\nMzAxMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAWgBQGgzaN2tRzErVZCEe7Ucju\nTY5XBzAKBggqhkjOPQQDAgNHADBEAiB+Oc4DPody43cZ0e+MY7F63DnIPM5xtgwR\nG6IYdhXiAwIgYxOlBxxupGDvvhXyS7IV8KadGD8LVm8G059OJC9vIG0=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBUTCB+KADAgECAggYXbRNlzUisDAKBggqhkjOPQQDAjANMQswCQYDVQQDEwJj\nYTAeFw0yNTA4MjEwNjI3NTVaFw0yNjA4MjEwNjI3NTVaMA0xCzAJBgNVBAMTAmNh\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFWG+fC3bE4X0oOHIGbH0d1VY1vQc\nDeu/ey1+bCXTsyFLld8rwk5KDjPGI+QGlL5lnEVYWZUQ8QQLYQLhK//uKKNCMEAw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFAaDNo3a\n1HMStVkIR7tRyO5NjlcHMAoGCCqGSM49BAMCA0gAMEUCIAJLtjBdGvDYO18xZ2wI\nJYyzoxN8K4I5VodVwuF/4J5cAiEAmMeY8VbFFKBRLJhnd2wPHaK3pbbMozJ99nSC\nI2xUCvs=\n-----END CERTIFICATE-----\n",
        "peer_certificates_decoded": [
            {
                "issuer": "CN=ca",
                "not_after": "2026-08-21T06:27:55Z",
                "not_before": "2025-08-21T06:27:55Z",
                "serial_number": "1755757675088411914",
                "subject": "CN=client"
            },
            {
                "issuer": "CN=ca",
                "not_after": "2026-08-21T06:27:55Z",
                "not_before": "2025-08-21T06:27:55Z",
                "serial_number": "1755757675086684848",
                "subject": "CN=ca"
            }
        ],
        "version": "TLS 1.3"
    },
    "url": "/foobar"
}
```

</details>

#### <code>/status</code> - Responds with the provided HTTP status code. Default: 200 OK.

<details>

##### Description

By default, this endpoint returns an HTTP 200 OK status code.
You can modify the status code using the `set` query parameter.
The server will persist the updated status code, and subsequent requests to `/status` will return the new status code until it is changed again.

##### Parameters

| Name | Description                                 |
| ---- | ------------------------------------------- |
| set  | HTTP status code to persist (integer).      |

##### Responses

| Status | Description                     |
| ------ | ------------------------------- |
| code   | Request details in JSON format. |

`code` is the HTTP status code set by the `set` query parameter or `200 OK` by default.
Body contains the request details in JSON format as described in the `/*` endpoint.

##### Example

```console
$ http GET http://localhost:8080/status
```

```http
HTTP/1.1 200 OK
Content-Length: 0
Date: Fri, 29 Nov 2024 06:24:46 GMT

... Request details in JSON format ...
```

```console
$ http GET http://localhost:8080/status?set=503
```

```http
HTTP/1.1 503 Service Unavailable
Content-Length: 0
Date: Sun, 19 Oct 2025 18:05:20 GMT

... Request details in JSON format ...
```

</details>

#### <code>/status/{code}</code>

Returns the specified HTTP status code.

<details>

##### Parameters

| Status | Description                     |
| ------ | ------------------------------- |
| code   | Request details in JSON format. |

`code` is the HTTP status code specified in the URL path.
Body contains the request details in JSON format as described in the `/*` endpoint.

Optionally, you can include additional HTTP headers in the response by providing a JSON object in the body or using a query string.

##### Example

```sh
$ http POST http://localhost:8080/status/301 Location=http://localhost/bar
```

Body of the request

```json
{
  "Location": "http://localhost/bar"
}
```

Response:

```http
HTTP/1.1 301 Moved Permanently
Content-Length: 0
Date: Fri, 29 Nov 2024 06:10:25 GMT
Location: http://localhost/bar

... Request details in JSON format ...
```

```sh
$ http "http://localhost:8080/status/200?Set-Cookie=foo%3Dbar&Set-Cookie=hello%3Dworld"
```

Response:

```http
HTTP/1.1 200 OK
Content-Length: 0
Date: Sun, 15 Dec 2024 12:00:06 GMT
Set-Cookie: foo=bar
Set-Cookie: hello=world

... Request details in JSON format ...
```

</details>

#### <code>/sse</code> - Server-Sent Events (SSE) endpoint that sends a message every second.

<details>

##### Responses

| Status | Description            |
| ------ | ---------------------- |
| 200 OK | Server is operational. |

##### Example

Server will respond with `Content-Type: text/event-stream` with the following content:

```sh
$ http http://localhost:8080/sse
```

```http
HTTP/1.1 200 OK
Cache-Control: no-cache
Connection: keep-alive
Content-Type: text/event-stream
Date: Wed, 19 Feb 2025 10:10:15 GMT
Transfer-Encoding: chunked

data: { "counter": "1", "timestamp": "2025-02-19T12:10:15+02:00" }

data: { "counter": "2", "timestamp": "2025-02-19T12:10:16+02:00" }
...
```

</details>

#### <code>/websocket</code> - WebSocket endpoint that sends a text frame every second.

#### <code>/upload</code> - File upload.

<details>

##### Description

Accepts POST requests with bodies of any size.
Responds with the total number of bytes received, rather than request details.

##### Parameters

| Name     | Description                                                                         | Default |
| -------- | ----------------------------------------------------------------------------------- | ------- |
| throttle | Throttle the upload speed to bytes/sec (integer with optional suffix "K", "M", "G") |         |

##### Responses

| Status | Description                 |
| ------ | --------------------------- |
| 200 OK | Uploaded bytes JSON format. |

Following fields is included in the response:

- `bytes_uploaded`: Length of the request body.

##### Example

```sh
$ dd if=/dev/zero bs=10M count=1 | http POST http://localhost:8080/upload
```

```http
HTTP/1.1 200 OK
content-length: 26
content-type: application/json
date: Thu, 21 Aug 2025 12:27:06 GMT
server: envoy
x-envoy-upstream-service-time: 0

{
    "bytes_uploaded": 1048576
}
```

To upload a file, while throttling the upload speed to 1MB/s at the server side:

```sh
$ dd if=/dev/zero bs=10M count=1 | http http://localhost:8080/upload?throttle=1M
```

</details>

#### <code>/download</code> - File download.

<details>

##### Description

Accepts GET requests and responds with a binary stream of bytes.
The number of bytes can be specified with the `bytes` query parameter.
The default size for the download is 1MB.
The response body consists of a sequence of bytes from 1 to 256.

##### Parameters

| Name     | Description                                                                           | Default |
| -------- | ------------------------------------------------------------------------------------- | ------- |
| bytes    | Number of bytes to download (integer)                                                 | 1048576 |
| throttle | Throttle the download speed to bytes/sec (integer with optional suffix "K", "M", "G") |         |

##### Responses

| Status | Description                |
| ------ | -------------------------- |
| 200 OK | File download in progress. |

##### Example

Download the default 1MB file:

```sh
$ http --download http://localhost:8080/download --output download.bin
```

Response headers:

```http
HTTP/1.1 200 OK
content-length: 1048576
content-type: application/octet-stream
date: Thu, 21 Aug 2025 16:37:15 GMT
server: envoy
x-envoy-upstream-service-time: 0
```

Download a 10-byte file:

```sh
$ http --download http://localhost:8080/download?bytes=10 --output download.bin
```

Download a 10MB file while throttling the upload speed to 1MB/s at the server side:

```sh
$ http --download http://localhost:8080/download?bytes=10M\&throttle=1M --output download.bin
```

</details>

#### <code>/metrics</code> - Metrics for monitoring.

<details>

##### Description

This endpoint provides Prometheus-compatible metrics for monitoring the server.

##### Responses

| Status | Description                              |
| ------ | ---------------------------------------- |
| 200 OK | Metrics in prometheus exposition format. |

##### Example

```console
$ http GET http://localhost:8080/metrics
```

```text
# HELP http_requests_total Total number of HTTP requests received.
# TYPE http_requests_total counter
http_requests_total{method="GET",status_code="200"} 5
...
```

See [metrics.go](metrics.go) for details about the available metrics.

</details>

#### <code>/grpc.EchoService/*</code> - gRPC Echo service.

<details>

##### Description

Endpoint that return details about incoming gRPC request.
For the service definition see [`proto/echo.proto`](proto/echo.proto).

##### Example

To invoke the gRPC Echo service, you can use the [`grpcurl`](https://github.com/fullstorydev/grpcurl) tool.
Install it with:

```sh
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3
```

To call the Echo method over HTTP/2:


```sh
$ grpcurl -cacert testdata/certs/ca.pem -proto proto/echo.proto -d '{"message": "Hello"}' localhost:8443 echo.EchoService/Echo
```

```json
{
  "message": "Hello",
  "headers": {
    ":authority": {
      "values": [
        "localhost:8443"
      ]
    },
    "content-type": {
      "values": [
        "application/grpc"
      ]
    },
    "grpc-accept-encoding": {
      "values": [
        "gzip"
      ]
    },
    "user-agent": {
      "values": [
        "grpcurl/dev-build (no version set) grpc-go/1.61.0"
      ]
    }
  },
  "remoteAddr": "127.0.0.1:54936",
  "tlsInfo": {
    "version": "TLS 1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "alpnNegotiatedProtocol": "h2"
  }
}
```

Or using H2C (plaintext) transport:

```sh
$ grpcurl -plaintext -proto proto/echo.proto -d '{"message": "Hello"}' localhost:8080 echo.EchoService/Echo
```

```json
{
  "message": "Hello",
  "headers": {
    ":authority": {
      "values": [
        "localhost:8080"
      ]
    },
    "content-type": {
      "values": [
        "application/grpc"
      ]
    },
    "grpc-accept-encoding": {
      "values": [
        "gzip"
      ]
    },
    "user-agent": {
      "values": [
        "grpcurl/dev-build (no version set) grpc-go/1.61.0"
      ]
    }
  },
  "remoteAddr": "127.0.0.1:60740"
}
```

</details>

#### <code>/apps/</code> - Returns a list of available applications.

#### <code>/apps/fetch.html</code> - Interactive HTTP request tool.

<details>

##### Description

A JavaScript application that enables users to make HTTP requests towards the
echoserver using different methods and view the responses.

![Image](https://github.com/user-attachments/assets/8dff4db9-fd9a-4b1c-86ac-e3be15d107cf)

</details>

#### <code>/apps/form.html</code> - HTML form submission.

<details>

##### Description

An HTML form that enables data submission using both `POST` and `GET` methods
towards the echoserver.

![Image](https://github.com/user-attachments/assets/0876d4fb-c9cf-4313-9a4a-d3ca40ecd378)

</details>

#### <code>/apps/oauth.html</code> - Interactive OAuth2 client.

<details>

##### Description

OAuth2-aware JavaScript application that implements the Authorization Code flow.
It allows users to interactively trigger login/refresh/logout and to make
authenticated requests towards the echoserver and view the responses.

![Image](https://github.com/user-attachments/assets/9d9f10d6-d110-4f11-b262-8018fbbdfc09)

</details>

#### <code>/apps/keycloak.html</code> - Interactive client using keycloak-js adapter.

<details>

##### Description

A JavaScript application that uses the [Keycloak-js](https://www.keycloak.org/securing-apps/javascript-adapter) JavaScript adapter to authenticate users.

![Image](https://github.com/user-attachments/assets/51f8c81c-dc27-46fb-9801-4966e3c88dce)

</details>

#### <code>/apps/streaming.html</code> - Streaming client.

<details>

##### Description

A JavaScript application that makes Server-Sent Events (SSE) or WebSocket connection towards the echoserver and displays the responses.

![Image](https://github.com/user-attachments/assets/e3555203-7994-46bd-879c-41a6094fc64f)

</details>

## Development

To build and run the echoserver locally, use the following commands:

```sh
make
./echoserver
```

To serve HTML files from the filesystem instead of using bundled files, use the
following command:

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

To test the OIDC applications, you need to have an OIDC provider. To run
Keyclaok as an OIDC provider, use the following command:

```sh
make run           # Generate test certificates and run echoserver in one terminal.
docker compose up  # Run Envoy and Keycloak in another terminal.
```

Then access the echoserver server at https://echoserver.127.0.0.1.nip.io/apps/
and Keycloak admin console at https://keycloak.127.0.0.1.nip.io/. Envoy will
validate JWT for endpoints matching with
https://echoserver.127.0.0.1.nip.io/protected.

> ⚠️ NOTE ⚠️
>
> You will get an error for first login, because the certificate is self-signed.
> To fix this, visit [Keycloak admin console](https://keycloak.127.0.0.1.nip.io/) once and accept the certificate.
>
> If running on Linux with firewall like UFW, traffic from docker bridge network to host network may be blocked.
> For UFW use `sudo ufw allow from 172.0.0.0/8`to allow traffic.

The admin console credentials are `admin:admin`, and the user credentials in `echoserver` realm are `joe:joe` and `jane:jane`.

Keycloak has been configured with the following clients:

- echoserver-public
- echoserver-public-dpop

The latter one is configured to require [DPoP](https://datatracker.ietf.org/doc/html/rfc9449).

[1]: https://wiki.wireshark.org/TLS#tls-decryption
