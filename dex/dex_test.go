package dex_test

import (
	"os"
	"testing"

	"github.com/bigkevmcd/testcontainer-modules/dex"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

var testImage = func() string {
	if v := os.Getenv("DEX_IMAGE"); v != "" {
		return v
	}

	return "dexidp/dex:v2.44.0-distroless"
}()

func TestStartDex(t *testing.T) {
	dexContainer, err := dex.Run(t.Context(),
		testImage,
		dex.WithConfig("testdata/config.yaml"),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, dexContainer)

	state, err := dexContainer.State(t.Context())
	require.NoError(t, err)
	require.True(t, state.Running)
}
