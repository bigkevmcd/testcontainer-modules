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
