Testcontainers for Go modules
=============================

## dex

```go
import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/bigkevmcd/testcontainer-modules/dex"
)

func TestDex(t *testing.T) {
	ctx := context.Background()

	dexContainer, err := dex.Run(ctx,
		"dexidp/dex:v2.44.0-distroless",
		dex.WithConfig("testdata/config.yaml"),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, dexContainer)

	state, err := dexContainer.State(ctx)
	require.NoError(t, err)
	require.True(t, state.Running)
}
```

This makes it easy to start a [Dex](https://dexidp.io/) OpenID Connect identity provider as a test container.

The container exposes Dex's HTTP port (`5556/tcp`) and waits for it to be listening before `Run` returns, so the
configuration you provide must have Dex listen on `0.0.0.0:5556`.

`WithConfig` copies a Dex configuration file from the host to `/etc/dex/config.docker.yaml`, which is where the
image's default command reads its configuration.

Use `dexContainer.Endpoint(ctx, "http")` (or `PortEndpoint`) to get the address of the running server.

The image can be overridden in this module's own tests with the `DEX_IMAGE` environment variable.
