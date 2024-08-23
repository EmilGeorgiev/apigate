package consumersecurity

import (
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks"
	"net/http"
	"strings"
)

// IPWhitelistingMiddleware adds IP whitelisting
func IPWhitelistingMiddleware(next http.Handler, config *buildingblocks.IPWhitelistingConfig) http.Handler {
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
