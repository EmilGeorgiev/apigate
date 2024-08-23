package main

import (
	"fmt"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks/backendsecurity"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks/consumersecurity"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func BuildMiddlewareChain(handler http.Handler, config *buildingblocks.Config) http.Handler {
	// Add middleware based on the configuration
	if config.BasicAuth != nil {
		handler = backendsecurity.BasicAuthMiddleware(handler, config.BasicAuth)
	}
	if config.OAuth2 != nil && config.OAuth2.Enabled {
		handler = backendsecurity.OAuth2Middleware(handler, config.OAuth2)
	}
	if config.CORS != nil && config.CORS.Enabled {
		handler = consumersecurity.CORSMiddleware(handler, config.CORS)
	}
	if config.IPWhitelisting != nil && config.IPWhitelisting.Enabled {
		handler = consumersecurity.IPWhitelistingMiddleware(handler, config.IPWhitelisting)
	}

	return logging(handler, config.TargetURL)
}

func logging(handler http.Handler, targetURL string) http.Handler {
	fmt.Println("Send request to the target server: ", targetURL)
	return handler
}

func main() {
	// Load the configuration
	config, err := buildingblocks.LoadConfig("config.yaml")
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
