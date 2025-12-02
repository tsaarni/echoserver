# Contributing

This guide is for those who wish to contribute to the project.

## Development

To build echoserver locally, use the following commands:

```sh
make
```

To serve HTML files from the filesystem instead of using bundled files, use the
following command:

```sh
./echoserver -live
```

As an alternative, you can build the project, generate test certificates, and run echoserver in both HTTP and HTTPS modes using the following `Makefile` target:

```sh
make run
```

To run test suite, use the following command:

```sh
make test
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

### Protobuf Code Generation

To generate protobuf code, ensure you have `protoc` and Go protobuf plugins installed.
Then run:

```sh
make generate-proto
```

### Vscode

To develop test cases for echoserver, use the e2e build tag in your VSCode settings:

```sh
mkdir -p .vscode
cat > .vscode/settings.json <<EOL
{
    "go.buildTags": "e2e"
}
EOL
```

This will ensure that the e2e code will be included in build by the VSCode Go extension.
