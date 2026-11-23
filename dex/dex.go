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

const defaultConfigPath = "/etc/dex/config.docker.yaml"

// WithConfig copies the Dex configuration file at configFile into the
// container, where the image's default command will read it.
func WithConfig(configFile string) testcontainers.CustomizeRequestOption {
	return func(req *testcontainers.GenericContainerRequest) error {
		if configFile == "" {
			return fmt.Errorf("WithConfig: configFile path cannot be empty")
		}

		req.Files = append(req.Files, testcontainers.ContainerFile{
			HostFilePath:      configFile,
			ContainerFilePath: defaultConfigPath,
			FileMode:          0o644,
		})

		return nil
	}
}
