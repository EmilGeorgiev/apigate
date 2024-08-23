package buildingblocks

import (
	"gopkg.in/yaml.v2"
	"os"
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
