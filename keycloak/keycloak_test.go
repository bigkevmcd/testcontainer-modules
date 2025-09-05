package keycloak_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Clarilab/gocloaksession"
	"github.com/Nerzal/gocloak/v13"
	"github.com/bigkevmcd/testcontainer-modules/keycloak"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

var testImage = func() string {
	if v := os.Getenv("KEYCLOAK_IMAGE"); v != "" {
		return v
	}

	return "quay.io/keycloak/keycloak:26.0.8-1"
}()

func TestKeycloakWithAdminCredentials(t *testing.T) {
	ctx := context.Background()

	keycloakContainer, err := keycloak.Run(ctx,
		testImage,
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	adminToken, err := keycloakContainer.GetBearerToken(ctx, "master", "administrator", "notpassword")
	assert.ErrorContains(t, err, "getting bearer token: invalid_grant")
	assert.Empty(t, adminToken)

	adminToken, err = keycloakContainer.GetBearerToken(ctx, "master", "administrator", "secretpassword")
	require.NoError(t, err)
	require.NotEmpty(t, adminToken)
}

func TestKeycloakWithImportRealm(t *testing.T) {
	ctx := context.Background()

	absPath, err := filepath.Abs(filepath.Join("testdata", "master-realm.json"))
	require.NoError(t, err)

	keycloakContainer, err := keycloak.Run(ctx,
		testImage,
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
		keycloak.WithImportRealm(absPath),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	adminToken, err := keycloakContainer.GetBearerToken(ctx, "master", "administrator", "secretpassword")
	require.NoError(t, err)

	// admin, user1, user2 come from the realm file.
	want := []user{
		{Username: "admin", Enabled: true, Attributes: map[string]any{"is_temporary_admin": []any{"true"}}},
		{Username: "administrator", Enabled: true, Attributes: map[string]any{"is_temporary_admin": []any{"true"}}},
		{Username: "user1", Enabled: true, Email: "user1@example.com", Firstname: "User", Lastname: "One", EmailVerified: false},
		{Username: "user2", Enabled: true, Email: "user2@example.com", Firstname: "User", Lastname: "Two", EmailVerified: true},
	}
	// TODO: Is the return ordering guaranteed?
	users := getUsers(ctx, t, "master", adminToken, keycloakContainer)
	assert.Equal(t, want, users)
}

func TestKeycloak(t *testing.T) {
	ctx := context.Background()
	keycloakContainer, err := keycloak.Run(ctx,
		testImage,
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	adminToken, err := keycloakContainer.GetBearerToken(ctx, "master", "administrator", "secretpassword")
	require.NoError(t, err)

	_, err = keycloakContainer.CreateRealm(ctx, adminToken, keycloak.RealmRepresentation{
		Realm:   "testing",
		Enabled: true,
	})
	require.NoError(t, err)

	require.NoError(t, keycloakContainer.EnableUnmanagedAttributes(ctx, "testing", adminToken))

	t.Run("creating a user", func(t *testing.T) {
		users := getUsers(ctx, t, "master", adminToken, keycloakContainer)
		want := []user{
			{
				Username: "administrator",
				Enabled:  true,
				Attributes: map[string]any{
					"is_temporary_admin": []any{
						"true",
					},
				},
			},
		}
		assert.Equal(t, want, users)

		_, err = keycloakContainer.CreateUser(ctx, "testing", adminToken, keycloak.UserRepresentation{
			Username:  "testing",
			Firstname: "Test", Lastname: "User",
			Email: "testing@example.com", EmailVerified: true,
			Attributes: map[string][]string{
				"testing": {"true"},
				"test":    {"user"},
			},
		})
		require.NoError(t, err)

		users = getUsers(ctx, t, "testing", adminToken, keycloakContainer)
		want = []user{
			{
				Username:  "testing",
				Firstname: "Test", Lastname: "User",
				Email:         "testing@example.com",
				EmailVerified: true,
				Attributes: map[string]any{
					"testing": []any{"true"},
					"test":    []any{"user"},
				},
			},
		}
		assert.Equal(t, want, users)
	})

	t.Run("setting a user password", func(t *testing.T) {
		userID, err := keycloakContainer.CreateUser(ctx, "master", adminToken, keycloak.UserRepresentation{
			Username:  "pwuser",
			Enabled:   true,
			Firstname: "PW", Lastname: "User",
			Email: "pwuser@example.com",
		})
		require.NoError(t, err)

		require.NoError(t, keycloakContainer.SetUserPassword(ctx, "master", adminToken, userID, "test-password"))

		_, err = keycloakContainer.GetBearerToken(ctx, "master", "pwuser", "test-password")
		require.NoError(t, err)
	})

	t.Run("creating a client", func(t *testing.T) {
		type client struct {
			ID       string `json:"id"`
			ClientID string `json:"clientId"`
			Name     string `json:"name"`
		}

		clientsPath, err := keycloakContainer.EndpointPath(ctx, "/admin/realms/master/clients")
		require.NoError(t, err)

		clients, err := get[[]client](ctx, adminToken, clientsPath)
		require.NoError(t, err)

		clientIDs := func() []string {
			var ids []string
			for _, client := range clients {
				ids = append(ids, client.ClientID)
			}
			return ids
		}()
		want := []string{
			"account",
			"account-console",
			"admin-cli",
			"broker",
			"master-realm",
			"security-admin-console",
			"testing-realm",
		}
		assert.Equal(t, want, clientIDs)

		err = keycloakContainer.CreateClient(ctx, "testing", adminToken, keycloak.ClientRepresentation{
			ClientID: "test-client",
			Enabled:  true,
			Secret:   "test-secret",
		})
		require.NoError(t, err)

		clients, err = get[[]client](ctx, adminToken, clientsPath)
		require.NoError(t, err)

		clientIDs = func() []string {
			var ids []string
			for _, client := range clients {
				ids = append(ids, client.ClientID)
			}
			sort.Strings(ids)

			return ids
		}()
		want = []string{
			"account",
			"account-console",
			"admin-cli",
			"broker",
			"master-realm",
			"security-admin-console",
			"testing-realm",
		}
		sort.Strings(clientIDs)
		assert.Equal(t, want, clientIDs)
	})

	t.Run("getting a client", func(t *testing.T) {
		newClient, err := keycloakContainer.GetClient(ctx, "testing", adminToken, "unknown-client")
		assert.ErrorContains(t, err, "unknown client")
		assert.Empty(t, newClient)

		err = keycloakContainer.CreateClient(ctx, "testing",
			adminToken, keycloak.ClientRepresentation{
				ClientID:                  "named-client",
				Enabled:                   true,
				Protocol:                  "openid-connect",
				DirectAccessGrantsEnabled: true,
			})
		require.NoError(t, err)
		newClient, err = keycloakContainer.GetClient(ctx, "testing", adminToken, "named-client")
		assert.NoError(t, err)
		assert.NotEmpty(t, newClient)
		assert.Equal(t, "named-client", newClient.ClientID)
	})

	t.Run("adding a role to a newly created client", func(t *testing.T) {
		err := keycloakContainer.CreateClient(ctx, "testing",
			adminToken, keycloak.ClientRepresentation{
				ClientID:                  "new-client",
				Enabled:                   true,
				ServiceAccountsEnabled:    true,
				Protocol:                  "openid-connect",
				DirectAccessGrantsEnabled: true,
				Attributes: map[string]string{
					"access.token.lifespan": "3600",
				},
			})
		require.NoError(t, err)
		newClient, err := keycloakContainer.GetClient(ctx, "testing", adminToken, "new-client")
		require.NoError(t, err)
		assert.NotEmpty(t, newClient)

		clientSecret, err := keycloakContainer.GetClientSecret(ctx, "testing", adminToken, newClient.ID)
		require.NoError(t, err)

		assert.Equal(t, clientSecret, newClient.Secret)

		keycloakEndpoint, err := keycloakContainer.Endpoint(ctx, "http")
		require.NoError(t, err)

		session, err := gocloaksession.NewSession("new-client", clientSecret, "testing", keycloakEndpoint)
		require.NoError(t, err)
		clientAuthToken, err := session.GetKeycloakAuthToken()
		require.NoError(t, err)

		// Before adding permissions querying for users should get a 403.
		realmUsers, err := session.GetGoCloakInstance().GetUsers(ctx, clientAuthToken.AccessToken, "testing", gocloak.GetUsersParams{
			Enabled: gocloak.BoolP(true),
		})

		require.ErrorContains(t, err, "Forbidden")
		assert.Empty(t, realmUsers)

		require.NoError(t, keycloakContainer.AddClientRoleToServiceAccount(ctx, "testing", adminToken, newClient.ID, "view-users"))

		// Need to get a new Auth token after adding roles.
		require.NoError(t, session.ForceAuthenticate())
		clientAuthToken, err = session.GetKeycloakAuthToken()
		require.NoError(t, err)

		realmUsers, err = session.GetGoCloakInstance().GetUsers(ctx, clientAuthToken.AccessToken, "testing", gocloak.GetUsersParams{
			Enabled: gocloak.BoolP(true),
		})
		require.NoError(t, err)
		assert.Len(t, realmUsers, 1)
	})
}

func TestEnableUnmanagedAttributes(t *testing.T) {
	ctx := context.Background()
	keycloakContainer, err := keycloak.Run(ctx,
		testImage,
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	adminToken, err := keycloakContainer.GetBearerToken(ctx, "master", "administrator", "secretpassword")
	require.NoError(t, err)

	require.NoError(t, keycloakContainer.EnableUnmanagedAttributes(ctx, "master", adminToken))

	profilePath, err := keycloakContainer.EndpointPath(ctx, "/admin/realms/master/users/profile")
	require.NoError(t, err)
	profile, err := get[map[string]any](ctx, adminToken, profilePath)
	require.NoError(t, err)

	require.Equal(t, "ENABLED", profile["unmanagedAttributePolicy"])
}

func get[T any](ctx context.Context, token, queryURL string) (T, error) {
	var m T

	r, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return m, err
	}

	r.Header.Add("Accept", "application/json")
	r.Header.Add("Authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return m, err
	}

	if res.StatusCode != http.StatusOK {
		return m, keycloak.ReadKeycloakError(res)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return m, err
	}
	if err := res.Body.Close(); err != nil {
		return m, err
	}

	if err := json.Unmarshal(body, &m); err != nil {
		return m, err
	}

	return m, nil
}

type user struct {
	Username      string         `json:"username"`
	Enabled       bool           `json:"enabled"`
	Firstname     string         `json:"firstName"`
	Lastname      string         `json:"lastName"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"emailVerified"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

func getUsers(ctx context.Context, t *testing.T, realmName, token string, keycloakContainer *keycloak.KeycloakContainer) []user {
	t.Helper()
	usersPath, err := keycloakContainer.EndpointPath(ctx, path.Join("/admin", "realms", realmName, "users"))
	require.NoError(t, err)

	users, err := get[[]user](ctx, token, usersPath)
	require.NoError(t, err)

	return users
}
