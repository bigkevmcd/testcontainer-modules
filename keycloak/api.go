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

// CreateClientRequest provides fields for creating clients.
// Based on Keycloak's ClientRepresentation
type CreateClientRequest struct {
	ClientID                  string            `json:"clientId"`
	Name                      string            `json:"name,omitempty"`
	Description               string            `json:"description,omitempty"`
	Enabled                   bool              `json:"enabled"`
	ClientAuthenticatorType   string            `json:"clientAuthenticatorType,omitempty"`
	Secret                    string            `json:"secret,omitempty"`
	RedirectUris              []string          `json:"redirectUris,omitempty"`
	WebOrigins                []string          `json:"webOrigins,omitempty"`
	NotBefore                 int32             `json:"notBefore,omitempty"`
	BearerOnly                bool              `json:"bearerOnly"`
	ConsentRequired           bool              `json:"consentRequired"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	PublicClient              bool              `json:"publicClient"`
	FrontchannelLogout        bool              `json:"frontchannelLogout"`
	Protocol                  string            `json:"protocol,omitempty"`
	Attributes                map[string]string `json:"attributes,omitempty"`
	FullScopeAllowed          bool              `json:"fullScopeAllowed"`
	NodeReRegistrationTimeout int32             `json:"nodeReRegistrationTimeout,omitempty"`
	DefaultClientScopes       []string          `json:"defaultClientScopes,omitempty"`
	OptionalClientScopes      []string          `json:"optionalClientScopes,omitempty"`
}
