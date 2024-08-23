package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// Config struct for YAML configuration
type Config struct {
	TargetURL      string                `yaml:"target_url"`
	BasicAuth      *BasicAuthConfig      `yaml:"basic_auth"`
	OAuth2         *OAuth2Config         `yaml:"oauth2"`
	CORS           *CORSConfig           `yaml:"cors"`
	IPWhitelisting *IPWhitelistingConfig `yaml:"ip_whitelisting"`
}

// BasicAuthConfig represents basic authentication configuration
type BasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// OAuth2Config represents OAuth2 configuration
type OAuth2Config struct {
	Enabled      bool `yaml:"enabled"`
	ClientID     string
	ClientSecret string
	TokenURL     string
}

// CORSConfig represents CORS configuration
type CORSConfig struct {
	Enabled bool `yaml:"enabled"`
}

// IPWhitelistingConfig represents IP whitelisting configuration
type IPWhitelistingConfig struct {
	Enabled bool     `yaml:"enabled"`
	IPs     []string `yaml:"ips"`
}

// LoadConfig loads the configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// BasicAuthMiddleware adds basic authentication
func BasicAuthMiddleware(next http.Handler, config *BasicAuthConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != config.Username || pass != config.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var expiresAt time.Time
var tokenResp TokenResponse

// OAuth2Middleware adds OAuth2 authentication
func OAuth2Middleware(next http.Handler, config *OAuth2Config) http.Handler {
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

func getAccessToken(config *OAuth2Config) (TokenResponse, error) {
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
		return TokenResponse{}, fmt.Errorf("failed to get a token: %v", body)
	}

	var tokenResp TokenResponse
	if err = json.Unmarshal(body, &tokenResp); err != nil {
		return TokenResponse{}, fmt.Errorf("failed to unmarshal token response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		return TokenResponse{}, errors.New("access token is empty")
	}
	return tokenResp, nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// CORSMiddleware adds CORS headers
func CORSMiddleware(next http.Handler, config *CORSConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// IPWhitelistingMiddleware adds IP whitelisting
func IPWhitelistingMiddleware(next http.Handler, config *IPWhitelistingConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.Enabled {
			clientIP := r.RemoteAddr
			forwardedFor := r.Header.Get("X-Forwarded-For")
			if forwardedFor != "" {
				clientIP = strings.Split(forwardedFor, ",")[0]
			}

			allowed := false
			for _, ip := range config.IPs {
				if strings.TrimSpace(clientIP) == ip {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func BuildMiddlewareChain(handler http.Handler, config *Config) http.Handler {
	// Add middleware based on the configuration
	if config.BasicAuth != nil {
		handler = BasicAuthMiddleware(handler, config.BasicAuth)
	}
	if config.OAuth2 != nil && config.OAuth2.Enabled {
		handler = OAuth2Middleware(handler, config.OAuth2)
	}
	if config.CORS != nil && config.CORS.Enabled {
		handler = CORSMiddleware(handler, config.CORS)
	}
	if config.IPWhitelisting != nil && config.IPWhitelisting.Enabled {
		handler = IPWhitelistingMiddleware(handler, config.IPWhitelisting)
	}
	return handler
}

func main() {
	// Load the configuration
	config, err := LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Parse the target URL
	targetURL, err := url.Parse(config.TargetURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}

	//urll, _ := url.Parse(config.TargetURL)

	// Create a reverse proxy
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(targetURL)
			r.Out.Host = r.In.Host // if desired
		},
		//Director:       nil,
		//Transport:      nil,
		//FlushInterval:  0,
		//ErrorLog:       nil,
		//BufferPool:     nil,
		//ModifyResponse: nil,
		//ErrorHandler:   nil,
	}

	// Build the middleware chain
	handler := BuildMiddlewareChain(proxy, config)

	// Start the server
	port := "8080" // Port can be made configurable as well
	log.Printf("Starting proxy server on port %s, forwarding to %s", port, config.TargetURL)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
