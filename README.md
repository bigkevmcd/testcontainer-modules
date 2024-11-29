Testcontainers for Go modules
=============================

This provides additional modules for use with ["Testcontainers for Go"](https://golang.testcontainers.org/).

## keycloak

```go
import (
	"testing"

	"github.com/stretchr/testify/require"

	"github/bigkevmcd/testcontainer-modules/keycloak"
)

func TestKeycloak(t *testing.T) {
	ctx := context.Background()

	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, keycloakContainer)

	token, err := keycloakContainer.GetBearerToken(ctx, "administrator", "secretpassword")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	err := keycloakContainer.CreateUser(ctx, token,
		keycloak.CreateUserRequest{Username: "testing-user", Enabled: true})
	require.NoError(t, err)
}
```

This makes it easy to start a [Keycloak](https://www.keycloak.org/) server as a test container.

The container is started in ["development mode"](https://www.keycloak.org/server/configuration#_starting_keycloak_in_development_mode).
