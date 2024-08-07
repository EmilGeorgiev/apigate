package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
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
	Enabled bool `yaml:"enabled"`
	// Add other fields needed for OAuth2 configuration
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

// OAuth2Middleware adds OAuth2 authentication
func OAuth2Middleware(next http.Handler, config *OAuth2Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Implement your OAuth2 logic here
		fmt.Println("OAuth2 middleware enabled")
		next.ServeHTTP(w, r)
	})
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
