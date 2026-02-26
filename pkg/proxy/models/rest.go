package models

// TokenResponse.
type TokenResponse struct {
	TokenType    string  `json:"token_type"`
	AccessToken  string  `json:"access_token"`
	IDToken      string  `json:"id_token"`
	RefreshToken string  `json:"refresh_token,omitempty"`
	Scope        string  `json:"scope,omitempty"`
	ExpiresIn    float64 `json:"expires_in"`
}

type DiscoveryResponse struct {
	ExpiredURL string `json:"expired_endpoint"`
	LogoutURL  string `json:"logout_endpoint"`
	TokenURL   string `json:"token_endpoint"`
	LoginURL   string `json:"login_endpoint"`
}
