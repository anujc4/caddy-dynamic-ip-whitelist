package ipgate

import (
	"net/http"
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
