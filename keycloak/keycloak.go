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
// realmName is the name of the realm e.g. "master"
//
// This uses the admin-cli client ID.
func (k *KeycloakContainer) GetBearerToken(ctx context.Context, realmName, username, password string) (string, error) {
	data := url.Values{}
	data.Set("client_id", defaultClientID)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("grant_type", "password")

	queryURL, err := k.EndpointPath(ctx, path.Join("/realms", realmName, "protocol", "openid-connect", "token"))
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("getting bearer token: %w", ReadKeycloakError(resp))
	}

	decoder := json.NewDecoder(resp.Body)
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return "", err
	}

	return result["access_token"].(string), nil
}

// EndpointPath returns a URL that is relative to the container endpoint.
//
// The path must be fully qualified e.g. /admin/realms/master/users
func (k *KeycloakContainer) EndpointPath(ctx context.Context, path string, opts ...func(*url.URL)) (string, error) {
	apiEndpoint, err := k.Endpoint(ctx, "http")
	if err != nil {
		return "", fmt.Errorf("getting the endpoint for %s: %w", path, err)
	}

	parsed, err := url.Parse(apiEndpoint)
	if err != nil {
		return "", fmt.Errorf("parsing endpoint %s: %w", apiEndpoint, err)
	}

	parsed.Path = path

	for _, opt := range opts {
		opt(parsed)
	}

	return parsed.String(), nil
}

// CreateRealm creates a realm with the provided representation.
//
// Returns the UUID of the created realm.
func (k *KeycloakContainer) CreateRealm(ctx context.Context, token string, rr RealmRepresentation) (string, error) {
	b, err := json.Marshal(rr)
	if err != nil {
		return "", fmt.Errorf("marshalling the realm creation to JSON: %w", err)
	}

	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms"))
	if err != nil {
		return "", fmt.Errorf("getting the path for realms: %w", err)
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
		return "", fmt.Errorf("creating new realm: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("creating new realm: %w", ReadKeycloakError(resp))
	}
	location := resp.Header.Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("invalid return location creating new realm: %w", err)
	}
	// Returns the URL of the created Resource, the ID is the UUID of the
	// created user.

	return path.Base(parsedURL.Path), nil
}

// CreateUser creates an user with the provided details.
//
// realmName is the name of the realm e.g. "master"
//
// Returns the UUID of the created user.
func (k *KeycloakContainer) CreateUser(ctx context.Context, realmName, token string, ur UserRepresentation) (string, error) {
	b, err := json.Marshal(ur)
	if err != nil {
		return "", fmt.Errorf("marshalling the user creation to JSON: %w", err)
	}

	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "users"))
	if err != nil {
		return "", fmt.Errorf("getting the path for the realm users: %w", err)
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
		return "", fmt.Errorf("creating new user: %w", ReadKeycloakError(resp))
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
//
// realmName is the name of the realm e.g. "master"
// userID is the ID of the user within ther realm e.g. "3af96c8e-4105-44eb-bf8c-2b44ff9194bb"
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_put_adminrealmsrealmusersuser_idreset_password
func (k *KeycloakContainer) SetUserPassword(ctx context.Context, realmName, token, userID, password string) error {
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

	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "users", userID, "reset-password"))
	if err != nil {
		return fmt.Errorf("getting the path for the password reset: %w", err)
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
		return fmt.Errorf("changing user password: %w", ReadKeycloakError(resp))
	}

	return nil
}

// EnableUnmanagedAttributes modifies the realm to allow unmanaged attributes.
//
// realmName is the name of the realm e.g. "master"
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmusersprofile
func (k *KeycloakContainer) EnableUnmanagedAttributes(ctx context.Context, realmName, token string) error {
	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "users", "profile"))
	if err != nil {
		return fmt.Errorf("getting the path for the realm profile: %w", err)
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
		return fmt.Errorf("enabling unmanaged attributes: %w", ReadKeycloakError(resp))
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
		return fmt.Errorf("updating realms profile: %w", ReadKeycloakError(resp))
	}

	return nil
}

// CreateClient creates an OIDC client.
//
// realmName is the name of the realm e.g. "master"
//
// Use GetClientUUID to get the ID of the newly created client.
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_post_adminrealmsrealmclients
func (k *KeycloakContainer) CreateClient(ctx context.Context, realmName, token string, cr ClientRepresentation) error {
	b, err := json.Marshal(cr)
	if err != nil {
		return fmt.Errorf("marshalling the client creation to JSON: %w", err)
	}

	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "clients"))
	if err != nil {
		return fmt.Errorf("getting the path for the realm clients: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("creating HTTP request for new client: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("creating new client: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("creating a client: %w", ReadKeycloakError(resp))
	}

	return nil
}

// GetClient gets the representation for a named client in a realm.
//
// realmName is the name of the realm e.g. "master"
// clientID is the ID of the client e.g. "test-client"
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmclients
func (k *KeycloakContainer) GetClient(ctx context.Context, realmName, token, clientID string) (repr *ClientRepresentation, clientErr error) {
	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "clients"),
		withQueryParams(url.Values{"clientId": []string{clientID}}))
	if err != nil {
		return nil, fmt.Errorf("getting the path for the generating the client UUID: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request for getting client UUID: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generating client secret: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			clientErr = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code getting client UUID: %w", ReadKeycloakError(resp))
	}

	var clients []ClientRepresentation
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&clients); err != nil {
		return nil, fmt.Errorf("parsing the response from getting client UUID: %w", err)
	}

	// TODO: error if more than one client?
	if len(clients) > 0 {
		return &clients[0], nil
	}

	return nil, fmt.Errorf("unknown client %v", clientID)
}

// GetClientSecret gets the token for accessing the API as a specific client.
//
// realmName is the name of the realm e.g. "master"
// clientID is the UUID of the client e.g. "6f18e746-df4a-4e8f-85db-3424e6c73b10"
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmclientsclient_uuidclient_secret
func (k *KeycloakContainer) GetClientSecret(ctx context.Context, realmName, token, clientID string) (secret string, clientErr error) {
	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "clients", clientID, "client-secret"))
	if err != nil {
		return "", fmt.Errorf("getting the path for the getting the client secret: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating HTTP request for getting client secret: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("generating client secret: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			clientErr = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid status code getting client secret: %w", ReadKeycloakError(resp))
	}

	var credentials CredentialRepresentation
	decoder := json.NewDecoder(resp.Body)

	if err := decoder.Decode(&credentials); err != nil {
		return "", fmt.Errorf("parsing the response from getting client secret: %w", err)
	}

	return credentials.Value, nil
}

// GenerateClientSecret regenerates the client token for a client.
//
// realmName is the name of the realm e.g. "master"
// clientID is the UUID of the client e.g. "6f18e746-df4a-4e8f-85db-3424e6c73b10"
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_post_adminrealmsrealmclientsclient_uuidclient_secret
func (k *KeycloakContainer) GenerateClientSecret(ctx context.Context, realmName, token, clientID string) (secret string, clientErr error) {
	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "clients", clientID, "client-secret"))
	if err != nil {
		return "", fmt.Errorf("getting the path for the generating the client secret: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating HTTP request for generating client secret: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("generating client secret: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			clientErr = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("invalid status code generating client secret: %w", ReadKeycloakError(resp))
	}

	var credentials CredentialRepresentation
	decoder := json.NewDecoder(resp.Body)

	if err := decoder.Decode(&credentials); err != nil {
		return "", fmt.Errorf("parsing the response from generating client secret: %w", err)
	}

	return credentials.Value, nil
}

// GetServiceAccountUser gets the service account user for a client.
//
// realmName is the name of the realm e.g. "master"
// clientID is the UUID of the client e.g. "6f18e746-df4a-4e8f-85db-3424e6c73b10"
//
// This user is automatically created when a client has serviceAccountsEnabled set to true.
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_get_adminrealmsrealmclientsclient_uuidservice_account_user
func (k *KeycloakContainer) GetServiceAccountUser(ctx context.Context, realmName, token, clientID string) (*UserRepresentation, error) {
	endpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "clients", clientID, "service-account-user"))
	if err != nil {
		return nil, fmt.Errorf("getting the path for the service account user: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request for service account user: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting service account user: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting service account user: %w", ReadKeycloakError(resp))
	}

	var user UserRepresentation
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()

	if err := decoder.Decode(&user); err != nil {
		return nil, fmt.Errorf("parsing service account user response: %w", err)
	}

	return &user, nil
}

// AddClientRoleToServiceAccount adds a client role to the service account user of a client.
// This is useful for granting permissions to service accounts for machine-to-machine communication.
//
// The roleName should be the name of an existing role in the target client.
// The clientID is the UUID of the client that owns the role.
//
// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_post_adminrealmsrealmusersuser_idrole_mappingsclientsClient_uuid
func (k *KeycloakContainer) AddClientRoleToServiceAccount(ctx context.Context, realmName, token, clientID, roleName string) error {
	serviceAccountUser, err := k.GetServiceAccountUser(ctx, realmName, token, clientID)
	if err != nil {
		return fmt.Errorf("getting service account user: %w", err)
	}

	realmManagementClient, err := k.GetClient(ctx, realmName, token, "realm-management")
	if err != nil {
		return fmt.Errorf("getting the realm-management client ID: %w", err)
	}

	role, err := k.getClientRole(ctx, realmName, token, realmManagementClient.ID, roleName)
	if err != nil {
		return fmt.Errorf("getting role %s: %w", roleName, err)
	}

	roleMappingsEndpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "users", serviceAccountUser.ID, "role-mappings", "clients", realmManagementClient.ID))
	if err != nil {
		return fmt.Errorf("getting the path for the client role mappings: %w", err)
	}

	roles := []RoleRepresentation{{Name: roleName, ID: role.ID}}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return fmt.Errorf("marshalling roles to JSON: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, roleMappingsEndpoint, bytes.NewReader(rolesJSON))
	if err != nil {
		return fmt.Errorf("creating HTTP request for adding client role: %w", err)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("adding client role to service account: %w", err)
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("adding client role to service account: %w", ReadKeycloakError(resp))
	}

	return nil
}

func (k *KeycloakContainer) getClientRole(ctx context.Context, realmName, token, clientID, roleName string) (*RoleRepresentation, error) {
	roleEndpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "clients", clientID, "roles", roleName))
	if err != nil {
		return nil, fmt.Errorf("getting the path for the client role: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, roleEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request for getting client role: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting client role mappings: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting client role mappings: %w", ReadKeycloakError(resp))
	}
	defer resp.Body.Close()

	var role RoleRepresentation
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&role); err != nil {
		return nil, fmt.Errorf("parsing client role response: %w", err)
	}

	return &role, nil
}

func (k *KeycloakContainer) getClientRoleMappings(ctx context.Context, realmName, token, serviceAccountID, clientID string) ([]RoleRepresentation, error) {
	roleMappingsEndpoint, err := k.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "users", serviceAccountID, "role-mappings/clients", clientID))
	if err != nil {
		return nil, fmt.Errorf("getting the path for the client role mappings: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, roleMappingsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request for role mappings: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting client role mappings: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting client role mappings: %w", ReadKeycloakError(resp))
	}
	defer resp.Body.Close()

	var roles []RoleRepresentation
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&roles); err != nil {
		return nil, fmt.Errorf("parsing client role response: %w", err)
	}

	return roles, nil
}

// KeycloakError parses a Keycloak error response.
type KeycloakError struct {
	Response   map[string]any
	StatusCode int
}

func (e KeycloakError) Error() string {
	if msg, ok := e.Response["error"]; ok {
		return msg.(string)
	}

	if msg, ok := e.Response["errorMessage"]; ok {
		return msg.(string)
	}

	return fmt.Sprintf("unknown error: %v", e.StatusCode)
}

// ReadKeycloakError parses an HTTP Response and returns an error with the
// message from Keycloak.
func ReadKeycloakError(resp *http.Response) error {
	defer resp.Body.Close()
	var response map[string]any
	decoder := json.NewDecoder(resp.Body)

	if err := decoder.Decode(&response); err != nil {
		return err
	}

	return KeycloakError{Response: response, StatusCode: resp.StatusCode}
}

func withQueryParams(s url.Values) func(*url.URL) {
	return func(u *url.URL) {
		u.RawQuery = s.Encode()
	}
}
