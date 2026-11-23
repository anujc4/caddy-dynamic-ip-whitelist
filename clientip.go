package ipgate

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// clientIP returns the canonical client IP, preferring Caddy's resolved
// client_ip over RemoteAddr. Returns "" if there is no valid IP.
func clientIP(r *http.Request) string {
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip = host
	}
	return canonicalIP(ip)
}

// canonicalIP unmaps IPv4-mapped addresses and drops zones. Returns "" if
// ip is invalid.
func canonicalIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return addr.Unmap().WithZone("").String()
}
