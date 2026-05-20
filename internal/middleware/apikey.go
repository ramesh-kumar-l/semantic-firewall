package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	fwerrors "github.com/ramesh152/semantic-firewall/pkg/errors"
)

// APIKeyAuth returns a middleware that requires a valid API key.
// Keys are accepted via "Authorization: Bearer <key>" or "X-API-Key: <key>".
// Comparison is constant-time to prevent timing attacks.
func APIKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isValidKey(extractAPIKey(r), validKeys) {
				writeError(w, http.StatusUnauthorized,
					fwerrors.New(fwerrors.CodeUnauthorized, "invalid or missing API key"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractAPIKey(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-API-Key")
}

func isValidKey(key string, validKeys []string) bool {
	kb := []byte(key)
	for _, k := range validKeys {
		if subtle.ConstantTimeCompare(kb, []byte(k)) == 1 {
			return true
		}
	}
	return false
}
