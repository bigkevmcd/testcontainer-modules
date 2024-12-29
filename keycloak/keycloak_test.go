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
		Username string `json:"username"`
		Enabled  bool   `json:"enabled"`
	}
	users, err := get[[]user](ctx, token, usersPath)
	require.NoError(t, err)

	// admin, user1, user2 come from the realm file.
	want := []user{
		{Username: "admin", Enabled: true},
		{Username: "administrator", Enabled: true},
		{Username: "user1", Enabled: true},
		{Username: "user2", Enabled: true},
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

	t.Run("creating a user", func(t *testing.T) {
		ctx := context.Background()
		type user struct {
			Username  string `json:"username"`
			Enabled   bool   `json:"enabled"`
			Firstname string `json:"firstName"`
			Lastname  string `json:"lastName"`
		}
		usersPath, err := keycloakContainer.EndpointPath(ctx, "/admin/realms/master/users")
		require.NoError(t, err)

		users, err := get[[]user](ctx, token, usersPath)
		require.NoError(t, err)

		want := []user{
			{Username: "administrator", Enabled: true},
		}
		assert.Equal(t, want, users)

		require.NoError(t, keycloakContainer.CreateUser(ctx, token, keycloak.CreateUserRequest{Username: "testing", Enabled: false, Firstname: "Test", Lastname: "User"}))

		users, err = get[[]user](ctx, token, usersPath)
		require.NoError(t, err)

		want = []user{
			{Username: "administrator", Enabled: true},
			{Username: "testing", Enabled: false, Firstname: "Test", Lastname: "User"},
		}
		// TODO: Is the return ordering guaranteed?
		assert.Equal(t, want, users)
	})
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
	if err := res.Body.Close(); err != nil {
		return m, err
	}
	if err != nil {
		return m, err
	}

	if err := json.Unmarshal(body, &m); err != nil {
		return m, err
	}

	return m, nil
}
