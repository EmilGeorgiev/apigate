package backendsecurity

import (
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks"
	"net/http"
)

// BasicAuthMiddleware adds basic authentication
func BasicAuthMiddleware(next http.Handler, config *buildingblocks.BasicAuthConfig) http.Handler {
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
