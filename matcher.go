package ipgate

import (
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchIPGate{})
}

// MatchIPGate matches requests whose client IP is in the shared
// whitelist managed by the ipgate_trigger handler. After a user
// authenticates and their IP is whitelisted, this matcher returns
// true for all subsequent requests from that IP until the TTL expires.
//
// This enables non-browser clients (mobile apps, media players, API
// consumers) to access services without cookie-based authentication.
//
// Caddyfile syntax:
//
//	@name ipgate
type MatchIPGate struct {
	whitelist *ipWhitelist
	logger    *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (MatchIPGate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.ipgate",
		New: func() caddy.Module { return new(MatchIPGate) },
	}
}

// Provision loads the shared IP whitelist from the usage pool.
func (m *MatchIPGate) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	wl := newIPWhitelist()
	val, loaded := store.LoadOrStore(storeKey, wl)
	if loaded {
		wl = val.(*ipWhitelist)
	}
	m.whitelist = wl
	return nil
}

// Match returns true if the client IP is whitelisted.
func (m *MatchIPGate) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if the client IP is whitelisted.
func (m *MatchIPGate) MatchWithError(r *http.Request) (bool, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	allowed := m.whitelist.IsAllowed(ip)
	if m.logger != nil {
		m.logger.Debug("ipgate match check",
			zap.String("ip", ip),
			zap.Bool("allowed", allowed),
		)
	}
	return allowed, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. This matcher
// accepts no arguments.
func (m *MatchIPGate) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		if d.NextBlock(0) {
			return d.Err("ipgate matcher does not accept blocks")
		}
	}
	return nil
}

var (
	_ caddyhttp.RequestMatcherWithError = (*MatchIPGate)(nil)
	_ caddy.Provisioner                 = (*MatchIPGate)(nil)
	_ caddyfile.Unmarshaler             = (*MatchIPGate)(nil)
)
