package backendsecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks"
	"io"
	"net/http"
	"net/url"
	"time"
)

var expiresAt time.Time
var tokenResp TokenResponse

// OAuth2Middleware adds OAuth2 authentication
func OAuth2Middleware(next http.Handler, config *buildingblocks.OAuth2Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Implement your OAuth2 logic here
		fmt.Println("OAuth2 middleware enabled")

		if expiresAt.Before(time.Now().UTC()) {
			token, err := getAccessToken(config)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				response := map[string]string{"error": err.Error()}
				json.NewEncoder(w).Encode(response)
				return
			}

			expiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
			tokenResp = token
		}

		// Add the Authorization header with the Bearer token
		r.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
		next.ServeHTTP(w, r)
	})
}

func getAccessToken(config *buildingblocks.OAuth2Config) (TokenResponse, error) {
	// Implement your OAuth2 logic here
	fmt.Println("OAuth2 middleware enabled")

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	req, err := http.NewRequest("POST", config.TokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to create request to get a token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to get a token from the oauth2 server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to read resp body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, fmt.Errorf("failed to get a token: %d %v", resp.StatusCode, string(body))
	}

	var tResp TokenResponse
	if err = json.Unmarshal(body, &tResp); err != nil {
		return TokenResponse{}, fmt.Errorf("failed to unmarshal token response: %v", err)
	}

	if tResp.AccessToken == "" {
		return TokenResponse{}, errors.New("access token is empty")
	}
	return tResp, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}
