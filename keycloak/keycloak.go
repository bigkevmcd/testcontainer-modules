package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	defaultHTTPPort   string = "8080/tcp"
	defaultCmd        string = "start-dev"
	importRealmCmd    string = "--import-realm"
	defaultClientID   string = "admin-cli"
	defaultImportPath string = "/opt/keycloak/data/import"
)

// KeycloakContainer executes Keycloak and provides additional functionality for
// interacting with a running Keycloak server.
type KeycloakContainer struct {
	testcontainers.Container
}

// CreateUserRequest provides fields for creating users.
type CreateUserRequest struct {
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
	// TODO: Extend the number of fields?
}

// Run creates an instance of the Keycloak container type.
func Run(ctx context.Context, img string, opts ...testcontainers.ContainerCustomizer) (*KeycloakContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        img,
		ExposedPorts: []string{defaultHTTPPort},
		Cmd:          []string{defaultCmd},
		WaitingFor:   wait.ForLog("Running the server in development mode."),
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
		return nil, fmt.Errorf("creating Keycloak container: %w", err)
	}

	return &KeycloakContainer{Container: container}, nil
}

// WithAdminCredentials sets the admin username and password.
func WithAdminCredentials(username, password string) testcontainers.CustomizeRequestOption {
	return func(req *testcontainers.GenericContainerRequest) error {
		// TODO: This should look to see what version is being used!

		if req.Env == nil {
			req.Env = map[string]string{}
		}
		// For Pre v26...
		// req.Env["KEYCLOAK_ADMIN"] = username
		// req.Env["KEYCLOAK_ADMIN_PASSWORD"] = password

		req.Env["KC_BOOTSTRAP_ADMIN_USERNAME"] = username
		req.Env["KC_BOOTSTRAP_ADMIN_PASSWORD"] = password

		return nil
	}
}

// WithImportRealm sets the container up to read from a Realm export.
func WithImportRealm(realmFile string) testcontainers.CustomizeRequestOption {
	if realmFile == "" {
		panic("WithImportRealm must provide a path")
	}

	return func(req *testcontainers.GenericContainerRequest) error {
		cf := testcontainers.ContainerFile{
			HostFilePath:      realmFile,
			ContainerFilePath: filepath.Join(defaultImportPath, filepath.Base(realmFile)),
			FileMode:          0o755,
		}
		req.Files = append(req.Files, cf)

		if len(req.Cmd) == 0 {
			req.Cmd = []string{defaultCmd, importRealmCmd}
			return nil
		}

		req.Cmd = append(req.Cmd, importRealmCmd)

		return nil
	}
}

// GetBearerToken makes a call to the OpenID endpoint to request a token.
//
// The request is authenticated with the provided username/password.
//
// The client_id defaults to "admin-cli".
func (k *KeycloakContainer) GetBearerToken(ctx context.Context, username, password string) (string, error) {
	data := url.Values{}
	data.Set("client_id", defaultClientID)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")

	queryURL, err := k.EndpointPath(ctx, "/realms/master/protocol/openid-connect/token")
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, queryURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		// TODO: What if this returns an error?
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid response status: %v", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	result := map[string]any{}
	err = decoder.Decode(&result)
	if err != nil {
		return "", err
	}

	return result["access_token"].(string), nil
}

// EndpointPath returns a URL that is relative to the container endpoint.
// The path must be fully qualified e.g. /admin/realms/master/users
func (k *KeycloakContainer) EndpointPath(ctx context.Context, path string) (string, error) {
	apiEndpoint, err := k.Endpoint(ctx, "http")
	if err != nil {
		return "", fmt.Errorf("getting the endpoint for %s: %s", path, err)
	}

	return apiEndpoint + path, nil
}

// CreateUser creates an enabled user with the provided username.
// TODO: What to do about realms?
func (k *KeycloakContainer) CreateUser(ctx context.Context, token string, ur CreateUserRequest) error {
	b, err := json.Marshal(ur)
	if err != nil {
		return fmt.Errorf("marshalling the user creation to JSON: %w", err)
	}

	endpoint, err := k.EndpointPath(ctx, "/admin/realms/master/users")
	if err != nil {
		return fmt.Errorf("getting the path for the realm users: %s", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("creating HTTP request for new user: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("creating new user: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("invalid status code creating new user: %v", resp.StatusCode)
	}

	return nil
}