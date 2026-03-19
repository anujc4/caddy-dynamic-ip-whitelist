package ipgate

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestMatchIPGate_Allowed(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("192.168.1.10", 1*time.Hour)

	m := &MatchIPGate{whitelist: wl}
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.10:54321"

	if !m.Match(r) {
		t.Error("expected match for whitelisted IP")
	}
}

func TestMatchIPGate_Denied(t *testing.T) {
	wl := newIPWhitelist()

	m := &MatchIPGate{whitelist: wl}
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "10.0.0.1:54321"

	if m.Match(r) {
		t.Error("expected no match for non-whitelisted IP")
	}
}

func TestMatchIPGate_Expired(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("192.168.1.10", 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	m := &MatchIPGate{whitelist: wl}
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.10:54321"

	if m.Match(r) {
		t.Error("expected no match for expired IP")
	}
}

func TestMatchIPGate_NoPort(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("192.168.1.10", 1*time.Hour)

	m := &MatchIPGate{whitelist: wl}
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.10"

	if !m.Match(r) {
		t.Error("expected match when RemoteAddr has no port")
	}
}

func TestMatchIPGate_AllowCIDR(t *testing.T) {
	wl := newIPWhitelist()
	m := &MatchIPGate{
		whitelist: wl,
		prefixes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}

	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "192.168.1.50:12345"

	if !m.Match(r) {
		t.Error("expected match for IP in allow CIDR")
	}
}

func TestMatchIPGate_AllowCIDR_NoMatch(t *testing.T) {
	wl := newIPWhitelist()
	m := &MatchIPGate{
		whitelist: wl,
		prefixes:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
	}

	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "10.0.0.1:12345"

	if m.Match(r) {
		t.Error("expected no match for IP outside allow CIDR")
	}
}

func TestMatchIPGate_AllowMultipleCIDRs(t *testing.T) {
	wl := newIPWhitelist()
	m := &MatchIPGate{
		whitelist: wl,
		prefixes: []netip.Prefix{
			netip.MustParsePrefix("192.168.1.0/24"),
			netip.MustParsePrefix("172.16.0.0/12"),
		},
	}

	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "172.20.0.5:12345"

	if !m.Match(r) {
		t.Error("expected match for IP in second allow CIDR")
	}
}

func TestMatchIPGate_AllowTakesPrecedence(t *testing.T) {
	wl := newIPWhitelist()
	// IP is NOT in whitelist, but IS in allow range
	m := &MatchIPGate{
		whitelist: wl,
		prefixes:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}

	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "10.0.0.1:12345"

	if !m.Match(r) {
		t.Error("expected allow to pass IP not in whitelist")
	}
}
