package dex

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestWithConfig(t *testing.T) {
	req := &testcontainers.GenericContainerRequest{}

	require.NoError(t, WithConfig("testdata/config.yaml")(req))

	require.Equal(t, []testcontainers.ContainerFile{{
		HostFilePath:      "testdata/config.yaml",
		ContainerFilePath: defaultConfigPath,
		FileMode:          0o644,
	}}, req.Files)
}

func TestWithConfigEmptyPath(t *testing.T) {
	req := &testcontainers.GenericContainerRequest{}

	require.ErrorContains(t, WithConfig("")(req), "cannot be empty")
	require.Empty(t, req.Files)
}
