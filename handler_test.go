package ipgate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
		MatchPaths:  []string{"/auth/callback"},
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
		MatchPaths:  []string{"/auth/callback"},
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
		MatchPaths:  []string{"/auth/callback"},
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
		MatchPaths:  []string{"/auth/callback"},
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

type bodyOnlyHandler struct{}

func (bodyOnlyHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	_, err := w.Write([]byte(`{"ok":true}`))
	return err
}

func TestTrigger_WhitelistsOnImplicitStatus(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPaths:  []string{"/auth/callback"},
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("POST", "http://example.com/auth/callback", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	if err := trigger.ServeHTTP(w, r, bodyOnlyHandler{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !wl.IsAllowed("10.0.0.1") {
		t.Error("expected IP to be whitelisted when upstream writes body without WriteHeader")
	}
}

func TestTrigger_WhitelistsOnAnyMatchPath(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPaths:  []string{"/api/auth/login", "/api/me"},
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("GET", "http://example.com/api/me", nil)
	r.RemoteAddr = "10.0.0.2:12345"
	w := httptest.NewRecorder()

	if err := trigger.ServeHTTP(w, r, stubHandler{status: 200}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !wl.IsAllowed("10.0.0.2") {
		t.Error("expected IP to be whitelisted for second match path")
	}
}

func TestStatusRecorder_IgnoresInformational(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &statusRecorder{
		ResponseWriterWrapper: caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
	}

	rec.WriteHeader(http.StatusEarlyHints)
	rec.WriteHeader(http.StatusOK)

	if rec.status != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.status)
	}
}

func TestTrigger_UnmarshalCaddyfileMultiplePaths(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ipgate_trigger {
		match_path /api/auth/login /api/auth/code
		match_path /api/me
		match_status 200
		ttl 4h
	}`)

	var trigger Trigger
	if err := trigger.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"/api/auth/login", "/api/auth/code", "/api/me"}
	if !slices.Equal(trigger.MatchPaths, want) {
		t.Errorf("expected paths %v, got %v", want, trigger.MatchPaths)
	}
}

func TestTrigger_SkipsInvalidClientIP(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPaths:  []string{"/auth/callback"},
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   wl,
		logger:      zap.NewNop(),
	}

	r, _ := http.NewRequest("POST", "http://example.com/auth/callback", nil)
	r.RemoteAddr = "@"

	if err := trigger.ServeHTTP(httptest.NewRecorder(), r, stubHandler{status: 200}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wl.Count() != 0 {
		t.Errorf("expected nothing whitelisted without a valid client IP, got %d entries", wl.Count())
	}
}

func TestTrigger_IgnoresConfiguredHeaders(t *testing.T) {
	wl := newIPWhitelist()
	trigger := &Trigger{
		MatchPaths:    []string{"/api/me"},
		MatchStatus:   200,
		TTL:           caddy.Duration(1 * time.Hour),
		IgnoreHeaders: []string{"X-API-Key", "Authorization"},
		whitelist:     wl,
		logger:        zap.NewNop(),
	}

	for _, header := range []string{"x-api-key", "Authorization"} {
		r, _ := http.NewRequest("GET", "http://example.com/api/me", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		r.Header.Set(header, "value")
		w := httptest.NewRecorder()

		if err := trigger.ServeHTTP(w, r, stubHandler{status: 200}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if w.Code != 200 {
			t.Errorf("expected upstream response to pass through, got %d", w.Code)
		}
		if wl.IsAllowed("10.0.0.1") {
			t.Errorf("expected request with %s header to not whitelist", header)
		}
	}

	r, _ := http.NewRequest("GET", "http://example.com/api/me", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	if err := trigger.ServeHTTP(httptest.NewRecorder(), r, stubHandler{status: 200}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !wl.IsAllowed("10.0.0.1") {
		t.Error("expected request without ignored headers to whitelist")
	}
}

func TestTrigger_Validate(t *testing.T) {
	valid := func() Trigger {
		return Trigger{
			MatchPaths:  []string{"/auth/callback"},
			MatchStatus: 200,
			TTL:         caddy.Duration(1 * time.Hour),
		}
	}
	tests := []struct {
		name   string
		modify func(*Trigger)
	}{
		{"status too low", func(t *Trigger) { t.MatchStatus = 99 }},
		{"status too high", func(t *Trigger) { t.MatchStatus = 600 }},
		{"negative ttl", func(t *Trigger) { t.TTL = caddy.Duration(-time.Hour) }},
	}

	base := valid()
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	for _, tt := range tests {
		trigger := valid()
		tt.modify(&trigger)
		if err := trigger.Validate(); err == nil {
			t.Errorf("%s: expected validation error", tt.name)
		}
	}
}

func TestTrigger_ProvisionRejectsNegativeSweepInterval(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	trigger := &Trigger{SweepInterval: caddy.Duration(-time.Minute)}
	if err := trigger.Provision(ctx); err == nil {
		t.Error("expected negative sweep_interval to be rejected")
	}
}

func TestTrigger_ProvisionRejectsUnsetNotifyEnv(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	trigger := &Trigger{NotifyURL: "https://ntfy.sh/{env.IPGATE_TEST_UNSET_TOPIC}"}
	err := trigger.Provision(ctx)
	if err == nil {
		_ = trigger.Cleanup()
		t.Fatal("expected unset env placeholder in notify_url to be rejected")
	}
	if strings.Contains(err.Error(), "ntfy.sh") {
		t.Errorf("error must not contain the URL: %v", err)
	}
}

func TestTrigger_UnmarshalCaddyfileErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"inline args", `ipgate_trigger /auth/callback {
			match_status 200
		}`},
		{"non-numeric status", `ipgate_trigger {
			match_status 200abc
		}`},
		{"ignore_header without args", `ipgate_trigger {
			ignore_header
		}`},
	}
	for _, tt := range tests {
		var trigger Trigger
		if err := trigger.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tt.input)); err == nil {
			t.Errorf("%s: expected parse error", tt.name)
		}
	}
}

func TestTrigger_UnmarshalCaddyfileIgnoreHeader(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ipgate_trigger {
		ignore_header X-API-Key Authorization
	}`)

	var trigger Trigger
	if err := trigger.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"X-API-Key", "Authorization"}
	if !slices.Equal(trigger.IgnoreHeaders, want) {
		t.Errorf("expected headers %v, got %v", want, trigger.IgnoreHeaders)
	}
}
