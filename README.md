Testcontainers for Go modules
=============================

This provides a [Keycloak](https://www.keycloak.org/) container based on [Testcontainers for Go](https://golang.testcontainers.org/).

The source is available [here](./keycloak).

## Contributing

Feel free to open issues against this repository https://github.com/bigkevmcd/testcontainer-modules

### Running the tests

You will require a running Docker service, alternatively testcontainers works with [Podman](https://podman-desktop.io/tutorial/testcontainers-with-podman).

```
$ cd keycloak
$ go test ./...
```
