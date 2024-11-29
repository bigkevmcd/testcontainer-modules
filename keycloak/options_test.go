package keycloak

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/testcontainers/testcontainers-go"
)

func TestWithAdminCredentials(t *testing.T) {
	type credentials struct {
		name     string
		password string
	}

	tests := map[string]struct {
		creds       credentials
		expectedEnv map[string]string
	}{
		"username and password": {
			creds: credentials{
				name:     "admin",
				password: "testingpassword",
			},
			expectedEnv: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
				"KC_BOOTSTRAP_ADMIN_PASSWORD": "testingpassword",
			},
		},
	}

	for k, tt := range tests {
		t.Run(k, func(t *testing.T) {
			req := &testcontainers.GenericContainerRequest{
				ContainerRequest: testcontainers.ContainerRequest{},
			}

			err := WithAdminCredentials(tt.creds.name, tt.creds.password)(req)
			require.NoError(t, err)

			require.Equal(t, tt.expectedEnv, req.Env)
		})
	}
}

func TestWithImportRealm(t *testing.T) {
	tests := map[string]struct {
		filename    string
		expectedReq testcontainers.ContainerRequest
	}{
		"simple path to file": {
			filename: "testdata/my-test-file",
			expectedReq: testcontainers.ContainerRequest{
				Cmd: []string{defaultCmd, importRealmCmd},
				Files: []testcontainers.ContainerFile{
					testcontainers.ContainerFile{
						HostFilePath:      "testdata/my-test-file",
						ContainerFilePath: filepath.Join(defaultImportPath, "my-test-file"),
						FileMode:          0o755,
					},
				},
			},
		},
	}

	for k, tt := range tests {
		t.Run(k, func(t *testing.T) {
			req := &testcontainers.GenericContainerRequest{
				ContainerRequest: testcontainers.ContainerRequest{},
			}

			err := WithImportRealm(tt.filename)(req)
			require.NoError(t, err)

			require.Equal(t, tt.expectedReq, req.ContainerRequest)
		})
	}
}
