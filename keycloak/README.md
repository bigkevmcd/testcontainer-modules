Testcontainers for Go modules
=============================

## keycloak

```go
import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bigkevmcd/testcontainer-modules/keycloak"
)

func TestKeycloak(t *testing.T) {
	ctx := context.Background()

	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, keycloakContainer)

	token, err := keycloakContainer.GetBearerToken(ctx, "master", "administrator", "secretpassword")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	err := keycloakContainer.CreateUser(ctx, "master", token,
		keycloak.UserRepresentation{Username: "testing-user", Enabled: true})
	require.NoError(t, err)

	// This allows the use of arbitrary attributes on created users.
	require.NoError(t, keycloakContainer.EnableUnmanagedAttributes(ctx, token))
}
```

This makes it easy to start a [Keycloak](https://www.keycloak.org/) server as a test container.

The container is started in ["development mode"](https://www.keycloak.org/server/configuration#_starting_keycloak_in_development_mode).
