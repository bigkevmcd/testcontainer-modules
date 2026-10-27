Testcontainers for Go modules
=============================

This provides [Keycloak](https://www.keycloak.org/) and [Dex](https://dexidp.io/) containers based on [Testcontainers for Go](https://golang.testcontainers.org/).

The source is available in the [Keycloak](./keycloak) and [Dex](./dex) modules.

## Contributing

Feel free to open issues against this repository https://github.com/bigkevmcd/testcontainer-modules

### Running the tests

You will require a running Docker service, alternatively testcontainers works with [Podman](https://podman-desktop.io/tutorial/testcontainers-with-podman).

```
$ cd keycloak
$ go test ./...
```
