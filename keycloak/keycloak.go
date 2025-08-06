package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
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
	Username      string `json:"username"`
	Enabled       bool   `json:"enabled"`
	Firstname     string `json:"firstName,omitempty"`
	Lastname      string `json:"lastName,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"emailVerified"`

	Attributes map[string][]string `json:"attributes,omitempty"`
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid response status: %v: %s", resp.StatusCode, b)
	}

	result := map[string]any{}
	err = json.Unmarshal(b, &result)
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
//
// Returns the UUID of the created user.
func (k *KeycloakContainer) CreateUser(ctx context.Context, token string, ur CreateUserRequest) (string, error) {
	b, err := json.Marshal(ur)
	if err != nil {
		return "", fmt.Errorf("marshalling the user creation to JSON: %w", err)
	}

	endpoint, err := k.EndpointPath(ctx, "/admin/realms/master/users")
	if err != nil {
		return "", fmt.Errorf("getting the path for the realm users: %s", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("creating HTTP request for new user: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("creating new user: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("invalid status code creating new user: %v", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid return location creating new user: %w", err)
	}
	// Returns the URL of the created Resource, the ID is the UUID of the
	// created user.

	return path.Base(parsedURL.Path), nil
}

// SetUserPassword sets a user password.
// TODO: What to do about realms?
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_put_adminrealmsrealmusersuser_idreset_password
func (k *KeycloakContainer) SetUserPassword(ctx context.Context, token, userID, password string) error {
	temporary := false
	cr := CredentialRepresentation{
		Type:      "password",
		Temporary: &temporary,
		Value:     password,
	}

	b, err := json.Marshal(cr)
	if err != nil {
		return fmt.Errorf("marshalling the credential representation to JSON: %w", err)
	}

	// TODO: improve the way these paths are calculated.
	endpoint, err := k.EndpointPath(ctx, fmt.Sprintf("/admin/realms/master/users/%s/reset-password", userID))
	if err != nil {
		return fmt.Errorf("getting the path for the password reset: %s", err)
	}

	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(b))
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

	if resp.StatusCode != http.StatusNoContent {
		// TODO: what to do in the event of an error?!
		b, _ := io.ReadAll(resp.Body)
		defer resp.Body.Close()

		return fmt.Errorf("invalid status code changing user password: %v: %s", resp.StatusCode, b)
	}

	return nil
}

// EnableUnmanagedAttributes modifies the realm to allow unmanaged attributes.
func (k *KeycloakContainer) EnableUnmanagedAttributes(ctx context.Context, token string) error {
	endpoint, err := k.EndpointPath(ctx, "/admin/realms/master/users/profile")
	if err != nil {
		return fmt.Errorf("getting the path for the realm profile: %s", err)
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating HTTP request for managed attributes: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("getting realm profile: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code getting realms profile: %v", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return err
	}

	parsed["unmanagedAttributePolicy"] = "ENABLED"

	b, err := json.Marshal(parsed)
	if err != nil {
		// TODO: Improve error!
		return err
	}

	req, err = http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("updating realm profile: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read body from invalid response %v: %w", resp.StatusCode, err)
		}
		defer resp.Body.Close()

		return fmt.Errorf("invalid status code updating realms profile: %v %s", resp.StatusCode, b)
	}

	return nil
}
