package ipgate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var store = caddy.NewUsagePool()

const storeKey = "ipgate"

func init() {
	caddy.RegisterModule(Trigger{})
}

// Trigger is an HTTP handler that watches upstream responses and whitelists
// the client IP when a response matches the configured path and status code.
// This enables IP-based access gating after a successful authentication flow.
//
// When placed on an authentication endpoint, it intercepts the response and
// if the path and status code match, the client's IP is added to a shared
// in-memory whitelist for the configured TTL. Other site blocks can then use
// the ipgate matcher to allow or deny requests based on whitelist membership.
//
// The module is auth-provider agnostic. Configure match_path and match_status
// to match any provider's successful authentication response.
//
// Caddyfile syntax:
//
//	ipgate_trigger {
//	    match_path   <path>
//	    match_status <code>
//	    ttl          <duration>
//	    sweep_interval <duration>
//	}
type Trigger struct {
	// The request path that signals a successful authentication.
	// Example: /api/webauthn/login/finish
	MatchPath string `json:"match_path"`

	// The HTTP status code that confirms authentication succeeded.
	// Example: 200
	MatchStatus int `json:"match_status"`

	// How long a whitelisted IP remains valid. Accepts any
	// duration string compatible with time.ParseDuration.
	// Example: 4h
	TTL caddy.Duration `json:"ttl"`

	// How often to scan and remove expired entries from the
	// whitelist. Default: 1m.
	SweepInterval caddy.Duration `json:"sweep_interval,omitempty"`

	whitelist *ipWhitelist
	logger    *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Trigger) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipgate_trigger",
		New: func() caddy.Module { return new(Trigger) },
	}
}

// Provision sets up the trigger, loads or creates the shared whitelist,
// and starts the background sweeper goroutine.
func (t *Trigger) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()

	if t.SweepInterval == 0 {
		t.SweepInterval = caddy.Duration(1 * time.Minute)
	}

	wl := newIPWhitelist()
	val, loaded := store.LoadOrStore(storeKey, wl)
	if loaded {
		wl = val.(*ipWhitelist)
	}
	t.whitelist = wl

	go t.runSweeper(ctx)

	return nil
}

// Validate ensures that all required fields are configured.
func (t *Trigger) Validate() error {
	if t.MatchPath == "" {
		return fmt.Errorf("match_path is required")
	}
	if t.MatchStatus == 0 {
		return fmt.Errorf("match_status is required")
	}
	if t.TTL == 0 {
		return fmt.Errorf("ttl is required")
	}
	return nil
}

// Cleanup decrements the reference count on the shared whitelist.
func (t *Trigger) Cleanup() error {
	_, _ = store.Delete(storeKey)
	return nil
}

// ServeHTTP intercepts responses to the configured path. If the upstream
// returns the expected status code, the client IP is added to the whitelist.
// For non-matching paths, requests pass through without overhead.
func (t *Trigger) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path != t.MatchPath {
		return next.ServeHTTP(w, r)
	}

	rec := &statusRecorder{ResponseWriterWrapper: caddyhttp.ResponseWriterWrapper{ResponseWriter: w}}
	err := next.ServeHTTP(rec, r)

	if rec.status == t.MatchStatus {
		ip, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			ip = r.RemoteAddr
		}
		t.whitelist.Add(ip, time.Duration(t.TTL))
		t.logger.Info("ip whitelisted",
			zap.String("ip", ip),
			zap.Duration("ttl", time.Duration(t.TTL)),
		)
	}

	return err
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (t *Trigger) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "match_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.MatchPath = d.Val()
			case "match_status":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var status int
				if _, err := fmt.Sscanf(d.Val(), "%d", &status); err != nil {
					return d.Errf("invalid status code: %s", d.Val())
				}
				t.MatchStatus = status
			case "ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ttl: %s", d.Val())
				}
				t.TTL = caddy.Duration(dur)
			case "sweep_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid sweep_interval: %s", d.Val())
				}
				t.SweepInterval = caddy.Duration(dur)
			default:
				return d.Errf("unrecognized subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

func (t *Trigger) runSweeper(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(t.SweepInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pruned := t.whitelist.Sweep()
			if pruned > 0 {
				t.logger.Debug("swept expired IPs", zap.Int("pruned", pruned))
			}
		case <-ctx.Done():
			return
		}
	}
}

// statusRecorder wraps a ResponseWriter to capture the status code
// written by the upstream handler.
type statusRecorder struct {
	caddyhttp.ResponseWriterWrapper
	status int
}

// WriteHeader captures the status code and delegates to the wrapped writer.
func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriterWrapper.WriteHeader(code)
}

var (
	_ caddyhttp.MiddlewareHandler = (*Trigger)(nil)
	_ caddy.Provisioner           = (*Trigger)(nil)
	_ caddy.Validator             = (*Trigger)(nil)
	_ caddy.CleanerUpper          = (*Trigger)(nil)
	_ caddyfile.Unmarshaler       = (*Trigger)(nil)
)
