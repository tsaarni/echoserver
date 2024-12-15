# Echoserver

This is a simple HTTP server that listens on incoming requests and echoes back information about the request.
It is inspired by the [echoserver](https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/images/echoserver) from the [ingress-controller-conformance](https://github.com/kubernetes-sigs/ingress-controller-conformance) project.
Additionally, the server can be used to test authentication and authorization features in ingress controllers by providing clients that make requests to the echoserver.

## Usage

If you want to run the server locally and you have `go`, you can use the following command:

```sh
go run github.com/tsaarni/echoserver@latest
```

Echoserver is available as a container image:

```
ghcr.io/tsaarni/tsaarni/echoserver:latest
```

The following environment variables can be used to configure the server:

| Variable        | Description                                                                                                           | Default |
| --------------- | --------------------------------------------------------------------------------------------------------------------- | ------- |
| `HTTP_PORT`     | Port for HTTP server                                                                                                  | `8080`  |
| `HTTPS_PORT`    | Port for HTTPS server                                                                                                 | `8443`  |
| `TLS_CERT_FILE` | Path to TLS certificate file                                                                                          |         |
| `TLS_KEY_FILE`  | Path to TLS key file                                                                                                  |         |
| `ENV_*`         | List of environment variables to be included in the `env` field of the JSON response and accessible in HTML templates |         |

The certificate and key files will be loaded from the filesystem every time a request is made to the server, so it is possible to update the certificate and key files without restarting the server.

The following environment variables are used when rendering the HTML pages:

| Variable       | Description            | Default   |
| -------------- | ---------------------- | --------- |
| `ENV_HOSTNAME` | Hostname of the server | localhost |

Following command line arguments can be given to the server:

| Argument | Description                                                                     | Default |
| -------- | ------------------------------------------------------------------------------- | ------- |
| `-live`  | Serve static files directly from the filesystem instead of using bundled files. | `false` |

### API

<details>
<summary><code>/*</code> Returns request details in JSON format.</summary>

#### Responses

| Status | Description                     |
| ------ | ------------------------------- |
| 200 OK | Request details in JSON format, including headers, method, URL, body, TLS information and decoded `Authorization` header (basic credentials and bearer token). |

##### Example

```console
$ http --cert client.pem --cert-key client-key.pem --verify root-ca.pem https://localhost:8443/foobar
```

```json
{
  "content_length": 0,
  "env": {
    "ENV_NAMESPACE": "mynamespace",
    "ENV_POD": "mypod"
  },
  "headers": {
    "Accept": ["*/*"],
    "Accept-Encoding": ["gzip, deflate, br"],
    "Connection": ["keep-alive"],
    "User-Agent": ["HTTPie/3.2.2"]
  },
  "host": "localhost:8443",
  "method": "GET",
  "proto": "HTTP/1.1",
  "remote": "127.0.0.1:53378",
  "tls": {
    "alpn_negotiated_protocol": "http/1.1",
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "peer_certificates": "-----BEGIN CERTIFICATE-----\nMIIBSzCB8qADAgECAggYDDuSRtpjxTAKBggqhkjOPQQDAjASMRAwDgYDVQQDEwdy\nb290LWNhMB4XDTI0MTEyODIwMjQxNloXDTI1MTEyODIwMjQxNlowETEPMA0GA1UE\nAxMGY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pRXW7ZNf4Zzi3Qw\nlk4tpGQwi0alJCAKxloR1PfYei1Ixh74Qz2qsrvdTFM40S2CELW4QjRAt0KYA047\n8VWoRaMzMDEwDgYDVR0PAQH/BAQDAgWgMB8GA1UdIwQYMBaAFAif/mnSoWsFX550\nsiR5/dzToWrZMAoGCCqGSM49BAMCA0gAMEUCIQD2mtIiZ/a4TO80KdHDnOwlsWPf\nVuZxTcRNPyBF4F/lVwIgOD7pdL4NfJfRrouUTGvj4ST0+VY2kz2KrkpY0ckmdq4=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBWzCCAQKgAwIBAgIIGAw7kka+ahUwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAxMH\ncm9vdC1jYTAeFw0yNDExMjgyMDI0MTZaFw0yNTExMjgyMDI0MTZaMBIxEDAOBgNV\nBAMTB3Jvb3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATUHqYZ2/Esrwf1\nL/+Pra4+q3mA5QeaAxzilwJvm/5Wjk3C+oxTBqgIiRErKQ7DTxkC0U3c5d5/Og6o\nZwGmYXOqo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV\nHQ4EFgQUCJ/+adKhawVfnnSyJHn93NOhatkwCgYIKoZIzj0EAwIDRwAwRAIgKAsF\nvgXxODXq5f6jUnIC7muCb/t6zKc0DbM+kTWo0dYCIAIPMKBuXtZVskFjty0zV/H7\nNMK3WmY4Veyco3eUSiQN\n-----END CERTIFICATE-----\n",
    "version": "TLS 1.3"
  },
  "url": "/foobar"
}
```

</details>

<details>
<summary><code>/apps/status</code> Returns a `200 OK` status, indicating the server is operational.</summary>

#### Responses

| Status | Description            |
| ------ | ---------------------- |
| 200 OK | Server is operational. |

#### Example

```console
$ http GET http://localhost:8080/apps/status
```

```http
HTTP/1.1 200 OK
Content-Length: 0
Date: Fri, 29 Nov 2024 06:24:46 GMT
```

</details>

<details>
<summary><code>/apps/status/{code}</code> Returns the specified HTTP status code.</summary>

#### Parameters

| Name | Description                 |
| ---- | --------------------------- |
| code | HTTP status code to return. |

Optionally, a JSON object can be provided in the body to include additional HTTP headers in the response.

#### Example

```sh
$ http POST http://localhost:8080/apps/status/301 Location=http://localhost/bar
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
```

</details>

<details>
<summary><code>/apps/fetch.html</code> Interactive HTTP request tool.</summary>

A JavaScript application that enables users to make HTTP requests towards the echoserver using different methods and view the responses.

![image](https://github.com/user-attachments/assets/1c325a58-2829-4549-8f70-d411b562190c)

</details>

<details>
<summary><code>/apps/form.html</code> HTML form submission.</summary>

An HTML form that enables data submission using both `POST` and `GET` methods towards the echoserver.

![image](https://github.com/user-attachments/assets/46d5deb3-e9f5-4f34-a114-3d9ab0219e0b)

</details>

<details>
<summary><code>/apps/oauth.html</code> Interactive Oauth2 client.</summary>

OAuth2-aware JavaScript application that implements the Authorization Code flow.
It allows users to interactively trigger login/refresh/logout and to make authenticated requests towards the echoserver and view the responses.

![image](https://github.com/user-attachments/assets/31f5da4b-e064-4ce4-89e8-9d28a7230716)

</details>

Example commands in the descriptions are given using the [HTTPie](https://httpie.io/) tool.

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

To run with Keyclaok as an OIDC provider, use the following command:

```sh
make run           # Run in one terminal
docker compose up  # Run in another terminal
```

Then access the echoserver server at https://echoserver.127.0.0.1.nip.io/apps/keycloak.html and Keycloak at https://keycloak.127.0.0.1.nip.io/.
