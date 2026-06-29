package ipgate

import (
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func clientIP(r *http.Request) string {
	if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && v != "" {
		return v
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
