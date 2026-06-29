package ipgate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type stubHandler struct {
	status int
}

func (h stubHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(h.status)
	return nil
}

func TestTrigger_WhitelistsOnMatch(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPath:   "/auth/callback",
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("POST", "http://example.com/auth/callback", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	err := trigger.ServeHTTP(w, r, stubHandler{status: 200})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !wl.IsAllowed("10.0.0.1") {
		t.Error("expected IP to be whitelisted after matching trigger")
	}
}

func TestTrigger_IgnoresNonMatchingPath(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPath:   "/auth/callback",
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("GET", "http://example.com/other", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	err := trigger.ServeHTTP(w, r, stubHandler{status: 200})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wl.IsAllowed("10.0.0.1") {
		t.Error("expected IP to not be whitelisted for non-matching path")
	}
}

func TestTrigger_IgnoresNonMatchingStatus(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPath:   "/auth/callback",
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("POST", "http://example.com/auth/callback", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	err := trigger.ServeHTTP(w, r, stubHandler{status: 401})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wl.IsAllowed("10.0.0.1") {
		t.Error("expected IP to not be whitelisted for non-matching status")
	}
}

func TestTrigger_WhitelistsResolvedClientIP(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPath:   "/auth/callback",
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("POST", "http://example.com/auth/callback", nil)
	r.RemoteAddr = "172.69.224.131:443"
	r = withClientIPVar(r, "163.116.177.107")
	w := httptest.NewRecorder()

	if err := trigger.ServeHTTP(w, r, stubHandler{status: 200}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !wl.IsAllowed("163.116.177.107") {
		t.Error("expected resolved visitor IP to be whitelisted")
	}
	if wl.IsAllowed("172.69.224.131") {
		t.Error("proxy connecting IP must not be whitelisted")
	}
}

func TestStatusRecorder_CapturesStatus(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &statusRecorder{
		ResponseWriterWrapper: caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
	}

	rec.WriteHeader(http.StatusCreated)

	if rec.status != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, rec.status)
	}
	if w.Code != http.StatusCreated {
		t.Errorf("expected underlying writer status %d, got %d", http.StatusCreated, w.Code)
	}
}
