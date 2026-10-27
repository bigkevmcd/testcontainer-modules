package dex

import (
	"context"
	"fmt"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const defaultHTTPPort = "5556/tcp"

// DexContainer executes Dex and provides additional functionality for
// interacting with a running Dex server.
type DexContainer struct {
	testcontainers.Container
}

// Run creates an instance of the Dex container type.
func Run(ctx context.Context, img string, opts ...testcontainers.ContainerCustomizer) (*DexContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        img,
		ExposedPorts: []string{defaultHTTPPort},
		WaitingFor:   wait.ForListeningPort(defaultHTTPPort),
	}

	genericContainerReq := testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	}

	for _, opt := range opts {
		if err := opt.Customize(&genericContainerReq); err != nil {
			return nil, err
		}
	}

	container, err := testcontainers.GenericContainer(ctx, genericContainerReq)
	if err != nil {
		return nil, fmt.Errorf("creating Dex container: %w", err)
	}

	return &DexContainer{Container: container}, nil
}
