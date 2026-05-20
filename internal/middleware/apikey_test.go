package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	inspectmw "github.com/ramesh152/semantic-firewall/internal/middleware"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func applyAuth(keys []string) http.Handler {
	return inspectmw.APIKeyAuth(keys)(okHandler())
}

func TestAPIKeyAuth_ValidBearer(t *testing.T) {
	h := applyAuth([]string{"secret-key"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestAPIKeyAuth_ValidXAPIKey(t *testing.T) {
	h := applyAuth([]string{"secret-key"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "secret-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestAPIKeyAuth_MultipleValidKeys(t *testing.T) {
	h := applyAuth([]string{"key-alpha", "key-beta"})
	for _, key := range []string{"key-alpha", "key-beta"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("key %q: want 200, got %d", key, w.Code)
		}
	}
}

func TestAPIKeyAuth_InvalidKey(t *testing.T) {
	h := applyAuth([]string{"secret-key"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for wrong key, got %d", w.Code)
	}
}

func TestAPIKeyAuth_MissingKey(t *testing.T) {
	h := applyAuth([]string{"secret-key"})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for missing key, got %d", w.Code)
	}
}

func TestAPIKeyAuth_BearerPrefixRequired(t *testing.T) {
	h := applyAuth([]string{"secret-key"})
	// Passing the key value without "Bearer " prefix should fail.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "secret-key")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 without Bearer prefix, got %d", w.Code)
	}
}

func TestAPIKeyAuth_EmptyKeyList(t *testing.T) {
	// No valid keys configured — all requests should be denied.
	h := applyAuth([]string{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "anything")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 with empty key list, got %d", w.Code)
	}
}
