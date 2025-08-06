package keycloak

// CredentialRepresentation represents credentials for a user or client
// TODO: Custom unmarshal timestamps from Keycloak!
//
// Converted from https://www.keycloak.org/docs-api/latest/rest-api/index.html#CredentialRepresentation
type CredentialRepresentation struct {
	Algorithm         string `json:"algorithm,omitempty"`
	Counter           int32  `json:"counter,omitempty"`
	Device            string `json:"device,omitempty"`
	Digits            int32  `json:"digits,omitempty"`
	HashedSaltedValue string `json:"hashedSaltedValue,omitempty"`
	HashIterations    int32  `json:"hashIterations,omitempty"`
	Period            int32  `json:"period,omitempty"`
	Salt              string `json:"salt,omitempty"`
	Temporary         *bool  `json:"temporary,omitempty"`
	Type              string `json:"type,omitempty"`
	Value             string `json:"value,omitempty"`
}

// RoleRepresentation represents a role in Keycloak
// Converted from https://www.keycloak.org/docs-api/latest/rest-api/index.html#RoleRepresentation
type RoleRepresentation struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite,omitempty"`
	ClientRole  bool   `json:"clientRole,omitempty"`
	ContainerID string `json:"containerId,omitempty"`
}

// UserRepresentation represents a user in Keycloak
// Simplified version for service account purposes.
type UserRepresentation struct {
	ID            string `json:"id,omitempty"`
	Username      string `json:"username"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"emailVerified"`
	Enabled       bool   `json:"enabled"`
	Firstname     string `json:"firstName,omitempty"`
	Lastname      string `json:"lastName,omitempty"`

	Attributes map[string][]string `json:"attributes,omitempty"`
}

// RealmRepresentation is used to create new Realms.
type RealmRepresentation struct {
	Realm   string `json:"realm"`
	Enabled bool   `json:"enabled"`
}

// ClientRepresentation describes a Keycloak client.
type ClientRepresentation struct {
	ID                        string            `json:"id,omitempty"`
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name,omitempty"`
	Description               string            `json:"description,omitempty"`
	Type                      string            `json:"type,omitempty"`
	Enabled                   bool              `json:"enabled"`
	Secret                    string            `json:"secret,omitempty"`
	PublicClient              bool              `json:"publicClient"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	DefaultRoles              []string          `json:"defaultRoles,omitempty"`
	Access                    map[string]any    `json:"access,omitempty"`
	Attributes                map[string]string `json:"attributes,omitempty"`
	Protocol                  string            `json:"protocol,omitempty"`

	// TODO: Extend the number of fields?
}
