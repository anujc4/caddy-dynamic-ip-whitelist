package ipgate

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MatchIPGate{})
}

// MatchIPGate matches requests whose client IP is in the shared
// whitelist managed by the ipgate_trigger handler, or falls within
// any of the configured allow CIDR ranges.
//
// After a user authenticates and their IP is whitelisted, this matcher
// returns true for all subsequent requests from that IP until the TTL
// expires. IPs in the allow ranges are always allowed without
// authentication.
//
// This enables non-browser clients (mobile apps, media players, API
// consumers) to access services without cookie-based authentication.
//
// Caddyfile syntax:
//
//	@name ipgate [allow <cidr> ...] [allow <cidr> ...]
type MatchIPGate struct {
	// CIDR ranges that are always allowed without being in the
	// whitelist. Example: 192.168.1.0/24, 172.16.0.0/12
	Allow []string `json:"allow,omitempty"`

	prefixes  []netip.Prefix
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

// Provision loads the shared IP whitelist and parses allow CIDRs.
func (m *MatchIPGate) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	for _, cidr := range m.Allow {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("invalid allow CIDR %q: %v", cidr, err)
		}
		m.prefixes = append(m.prefixes, prefix)
	}

	wl := newIPWhitelist()
	val, loaded := store.LoadOrStore(storeKey, wl)
	if loaded {
		wl = val.(*ipWhitelist)
	}
	m.whitelist = wl
	return nil
}

// Match returns true if the client IP is whitelisted or allowed.
func (m *MatchIPGate) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if the client IP is whitelisted or
// falls within a allow CIDR range.
func (m *MatchIPGate) MatchWithError(r *http.Request) (bool, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	addr, err := netip.ParseAddr(ip)
	if err == nil {
		for _, prefix := range m.prefixes {
			if prefix.Contains(addr) {
				if m.logger != nil {
					m.logger.Debug("ipgate allow match",
						zap.String("ip", ip),
						zap.String("cidr", prefix.String()),
					)
				}
				return true, nil
			}
		}
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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
// Syntax:
//
//	ipgate [allow <cidr> ...] [allow <cidr> ...]
func (m *MatchIPGate) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "allow":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.Allow = append(m.Allow, args...)
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

var (
	_ caddyhttp.RequestMatcherWithError = (*MatchIPGate)(nil)
	_ caddy.Provisioner                 = (*MatchIPGate)(nil)
	_ caddyfile.Unmarshaler             = (*MatchIPGate)(nil)
)
