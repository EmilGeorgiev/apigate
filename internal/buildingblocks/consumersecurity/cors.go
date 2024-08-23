package consumersecurity

import (
	"github.com/EmilGeorgiev/apigare/internal/buildingblocks"
	"net/http"
)

// CORSMiddleware adds CORS headers
func CORSMiddleware(next http.Handler, config *buildingblocks.CORSConfig) http.Handler {
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
