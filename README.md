# Echoserver

Echoserver is a simple HTTP server that listens on incoming requests and echoes back
information about the request. It is inspired by the
[echoserver](https://github.com/kubernetes-sigs/ingress-controller-conformance/tree/master/images/echoserver)
from the
[ingress-controller-conformance](https://github.com/kubernetes-sigs/ingress-controller-conformance)
project. Additionally, the server can be used to test authentication and
authorization features in ingress controllers by providing clients that make
requests to the echoserver.

## Usage

To run the server locally it can be installed or run directly using following commands:

```sh
go install github.com/tsaarni/echoserver@latest # Install the binary.
go run github.com/tsaarni/echoserver@latest     # Run the server without installing.
```

Echoserver is also available as a container image:

```
ghcr.io/tsaarni/tsaarni/echoserver:latest
```

Echoserver can be configured either using command line arguments or environment variables.
Command line arguments take precedence over environment variables.
Following table lists the available configuration options:

| Command line     | Variable        | Description                                                                                                            | Default |
| ---------------- | --------------- | ---------------------------------------------------------------------------------------------------------------------- | ------- |
| `-http-addr`     | `HTTP_ADDR`     | Address to bind the HTTP server socket.                                                                                | `:8080` |
| `-https-addr`    | `HTTPS_ADDR`    | Address to bind the HTTPS server socket.                                                                               | `:8443` |
| `-tls-cert-file` | `TLS_CERT_FILE` | Path to TLS certificate file.                                                                                          |         |
| `-tls-key-file`  | `TLS_KEY_FILE`  | Path to TLS key file.                                                                                                  |         |
|                  | `ENV_*`         | List of environment variables to be included in the `env` field of the JSON response and accessible in HTML templates. |         |
| `-live`          |                 | Serve static files directly from the `./apps` dorectory instead of using bundled files in the binary.                  | `false` |
|                  | `SSLKEYLOGFILE` | Path to write the TLS master secret log file to. See [Wireshark documentation][1] for mor information.                 |         |

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
  - `version`: TLS version.
- `query`: Query parameters of the request if the URL contains a query string.
- `form`: Form parameters of the request body, if the content type is `application/x-www-form-urlencoded`.
- `cookies`: Cookies in the request if the request had a `Cookie` header.
- `body`: Request body.
- `jwt`: JWT claims if the request had JWT in the `Authorization` header.
  - `header`: JWT header.
  - `claims`: JWT claims.
    - If the `claims` field contains `iat` or `exp` claims, they are converted to human-readable format in the `iat_date` and `exp_date` fields.
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
        "peer_certificates": "-----BEGIN CERTIFICATE-----\nMIIBRTCB7aADAgECAggYEv19hfUwQDAKBggqhkjOPQQDAjANMQswCQYDVQQDEwJj\nYTAeFw0yNDEyMjAyMDQ1MjJaFw0yNTEyMjAyMDQ1MjJaMBExDzANBgNVBAMTBmNs\naWVudDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCbhS9nzLiBuFGDUp+vRfUQZ\nJ/pnDgTuJpPWSuPOjDLtZuhewGo5qxBMQBdHUbLruhNQ3bbcfPXXSyMe/VDMb4Sj\nMzAxMA4GA1UdDwEB/wQEAwIFoDAfBgNVHSMEGDAWgBR3JxAyNeNiSa/7Kb8yAfms\np4ozDDAKBggqhkjOPQQDAgNHADBEAiB2U34rNm3HUIsCwyaaixxO0bFulIQbOs0L\nxWM0CqNH+gIgaNm4Yu6rmGb2Ct7+i/k166TtcoSxjvJ11CdEKNTiJos=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBUDCB+KADAgECAggYESedInsoiDAKBggqhkjOPQQDAjANMQswCQYDVQQDEwJj\nYTAeFw0yNDEyMTQyMTE0NDdaFw0yNTEyMTQyMTE0NDdaMA0xCzAJBgNVBAMTAmNh\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9tDgaO4FFTiQxMauwt1g6BBBmVQu\nkIHPh9diQDiRCPiwF6S+sTCdame3q2vFpyF6MqbmPgzzqjZefuzbQTD+m6NCMEAw\nDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFHcnEDI1\n42JJr/spvzIB+aynijMMMAoGCCqGSM49BAMCA0cAMEQCIFEik3jlxD2MF9wJfdA+\nD5LfA3PFx05dQluCOrANza1sAiBt2VP7MQit8RFQ50CHFydouIcVzMfKGJLVFrKk\n/+NV5A==\n-----END CERTIFICATE-----\n",
        "version": "TLS 1.3"
    },
    "url": "/foobar"
}
```
</details>

#### <code>/status</code> - Returns a `200 OK` status, indicating the server is operational.

<details>

##### Responses

| Status | Description            |
| ------ | ---------------------- |
| 200 OK | Server is operational. |

##### Example

```console
$ http GET http://localhost:8080/status
```

```http
HTTP/1.1 200 OK
Content-Length: 0
Date: Fri, 29 Nov 2024 06:24:46 GMT
```

</details>

#### <code>/status/{code}</code>
Returns the specified HTTP status code.
<details>

##### Parameters

| Name | Description                 |
| ---- | --------------------------- |
| code | HTTP status code to return. |

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
The admin console credentials are `admin:admin`, and the user credentials in `echoserver` realm are `joe:joe` and `jane:jane`.

[1]: https://wiki.wireshark.org/TLS#tls-decryption
