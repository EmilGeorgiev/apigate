package main

import (
	"fmt"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks/backendsecurity"
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks/consumersecurity"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func BuildMiddlewareChain(handler http.Handler, config *buildingblocks.Config) http.Handler {
	// Add middleware based on the configuration

	handler = buildingblocks.MetricsHandler(handler)

	if config.BasicAuth != nil {
		handler = backendsecurity.BasicAuthMiddleware(handler, config.BasicAuth)
	}
	if config.OAuth2 != nil {
		fmt.Println("0000000000000")
		handler = backendsecurity.OAuth2Middleware(handler, config.OAuth2)
	}
	if config.CORS != nil {
		handler = consumersecurity.CORSMiddleware(handler, config.CORS)
	}
	if config.IPWhitelisting != nil {
		handler = consumersecurity.IPWhitelistingMiddleware(handler, config.IPWhitelisting)
	}

	handler = logging(handler, config.TargetURL)

	return handler
}

func logging(next http.Handler, targetURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Send request to the target server: ", targetURL)
		next.ServeHTTP(w, r)
	})
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

	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/", handler)

	// Start the server
	port := "8181" // Port can be made configurable as well
	log.Printf("Starting proxy server on port %s, forwarding to %s", port, config.TargetURL)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
