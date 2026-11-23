package ipgate

import (
	"context"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func withClientIPVar(r *http.Request, ip string) *http.Request {
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: ip,
	})
	return r.WithContext(ctx)
}

func TestClientIP_PrefersResolvedVar(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "172.69.224.131:443"
	r = withClientIPVar(r, "163.116.177.107")

	if got := clientIP(r); got != "163.116.177.107" {
		t.Errorf("expected resolved client_ip, got %q", got)
	}
}

func TestClientIP_FallsBackToRemoteAddr(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.10:54321"

	if got := clientIP(r); got != "192.168.1.10" {
		t.Errorf("expected RemoteAddr host, got %q", got)
	}
}

func TestClientIP_FallsBackWhenVarEmpty(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.10:54321"
	r = withClientIPVar(r, "")

	if got := clientIP(r); got != "192.168.1.10" {
		t.Errorf("expected RemoteAddr fallback when var empty, got %q", got)
	}
}

func TestClientIP_NoPort(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.10"

	if got := clientIP(r); got != "192.168.1.10" {
		t.Errorf("expected raw RemoteAddr when no port, got %q", got)
	}
}

func TestClientIP_Canonicalizes(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"[::ffff:1.2.3.4]:443", "1.2.3.4"},
		{"[2001:DB8::1]:443", "2001:db8::1"},
		{"[fe80::1%eth0]:443", "fe80::1"},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://example.com/", nil)
		r.RemoteAddr = tt.remoteAddr
		if got := clientIP(r); got != tt.want {
			t.Errorf("clientIP(%q): expected %q, got %q", tt.remoteAddr, tt.want, got)
		}
	}
}

func TestClientIP_InvalidReturnsEmpty(t *testing.T) {
	for _, remoteAddr := range []string{"@", "", "not-an-ip:443"} {
		r, _ := http.NewRequest("GET", "http://example.com/", nil)
		r.RemoteAddr = remoteAddr
		if got := clientIP(r); got != "" {
			t.Errorf("clientIP(%q): expected empty, got %q", remoteAddr, got)
		}
	}
}
