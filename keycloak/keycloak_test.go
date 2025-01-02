package keycloak_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bigkevmcd/testcontainer-modules/keycloak"
	"github.com/testcontainers/testcontainers-go"
)

func TestKeycloakWithAdminCredentials(t *testing.T) {
	ctx := context.Background()

	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	token, err := keycloakContainer.GetBearerToken(ctx, "administrator", "notpassword")
	assert.ErrorContains(t, err, "invalid response status: 401")
	assert.Empty(t, token)

	token, err = keycloakContainer.GetBearerToken(ctx, "administrator", "secretpassword")
	require.NoError(t, err)

	require.NotEmpty(t, token)
}

func TestKeycloakWithImportRealm(t *testing.T) {
	ctx := context.Background()

	absPath, err := filepath.Abs(filepath.Join("testdata", "master-realm.json"))
	require.NoError(t, err)

	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
		keycloak.WithImportRealm(absPath),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	token, err := keycloakContainer.GetBearerToken(ctx, "administrator", "secretpassword")
	require.NoError(t, err)

	usersPath, err := keycloakContainer.EndpointPath(ctx, "/admin/realms/master/users")
	require.NoError(t, err)

	type user struct {
		Username      string `json:"username"`
		Enabled       bool   `json:"enabled"`
		Firstname     string `json:"firstName"`
		Lastname      string `json:"lastName"`
		Email         string `json:"email,omitempty"`
		EmailVerified bool   `json:"emailVerified"`
	}
	users, err := get[[]user](ctx, token, usersPath)
	require.NoError(t, err)

	// admin, user1, user2 come from the realm file.
	want := []user{
		{Username: "admin", Enabled: true},
		{Username: "administrator", Enabled: true},
		{Username: "user1", Enabled: true, Email: "user1@example.com", Firstname: "User", Lastname: "One", EmailVerified: false},
		{Username: "user2", Enabled: true, Email: "user2@example.com", Firstname: "User", Lastname: "Two", EmailVerified: true},
	}
	// TODO: Is the return ordering guaranteed?
	assert.Equal(t, want, users)

}

func TestKeycloak(t *testing.T) {
	ctx := context.Background()
	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	token, err := keycloakContainer.GetBearerToken(ctx, "administrator", "secretpassword")
	require.NoError(t, err)
	require.NoError(t, keycloakContainer.EnableUnmanagedAttributes(ctx, token))

	t.Run("creating a user", func(t *testing.T) {
		type user struct {
			Username      string              `json:"username"`
			Enabled       bool                `json:"enabled"`
			Firstname     string              `json:"firstName"`
			Lastname      string              `json:"lastName"`
			Email         string              `json:"email,omitempty"`
			EmailVerified bool                `json:"emailVerified"`
			Attributes    map[string][]string `json:"attributes"`
		}
		usersPath, err := keycloakContainer.EndpointPath(ctx, "/admin/realms/master/users")
		require.NoError(t, err)

		users, err := get[[]user](ctx, token, usersPath)
		require.NoError(t, err)

		want := []user{
			{
				Username: "administrator", Enabled: true,
				Attributes: map[string][]string{
					"is_temporary_admin": {"true"},
				},
			},
		}
		assert.Equal(t, want, users)

		require.NoError(t, keycloakContainer.CreateUser(ctx, token, keycloak.CreateUserRequest{
			Username: "testing", Enabled: false, Firstname: "Test", Lastname: "User",
			Email: "testing@example.com", EmailVerified: true,
			Attributes: map[string][]string{
				"testing": {"true"},
				"test":    {"user"},
			},
		}))

		users, err = get[[]user](ctx, token, usersPath)
		require.NoError(t, err)

		want = []user{
			{
				Username: "administrator", Enabled: true,
				Attributes: map[string][]string{
					"is_temporary_admin": {"true"},
				},
			},
			{
				Username: "testing", Enabled: false, Firstname: "Test", Lastname: "User",
				Email: "testing@example.com", EmailVerified: true,
				Attributes: map[string][]string{
					"testing": {"true"},
					"test":    {"user"},
				},
			},
		}
		// TODO: Is the return ordering guaranteed?
		assert.Equal(t, want, users)
	})
}

func TestEnableUnmanagedAttributes(t *testing.T) {
	ctx := context.Background()
	keycloakContainer, err := keycloak.Run(ctx,
		"quay.io/keycloak/keycloak:26.0.6-0",
		keycloak.WithAdminCredentials("administrator", "secretpassword"),
	)
	testcontainers.CleanupContainer(t, keycloakContainer)
	require.NoError(t, err)

	token, err := keycloakContainer.GetBearerToken(ctx, "administrator", "secretpassword")
	require.NoError(t, err)

	require.NoError(t, keycloakContainer.EnableUnmanagedAttributes(ctx, token))

	profilePath, err := keycloakContainer.EndpointPath(ctx, "/admin/realms/master/users/profile")
	require.NoError(t, err)
	profile, err := get[map[string]any](ctx, token, profilePath)
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
		return m, fmt.Errorf("invalid status code: %v", res.StatusCode)
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
