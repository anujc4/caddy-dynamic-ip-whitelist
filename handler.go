package ipgate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
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
//	    match_path   <path> [<path> ...]
//	    match_status <code>
//	    ttl          <duration>
//	    sweep_interval <duration>
//	    notify_url     <url>
//	    notify_token   <token>
//	}
type Trigger struct {
	// The request paths that signal a successful authentication.
	// Example: /api/auth/login, /api/me
	MatchPaths []string `json:"match_paths"`

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

	// URL to POST a plain-text notification to when a new IP is
	// whitelisted. Supports {env.*} placeholders. Optional.
	NotifyURL string `json:"notify_url,omitempty"`

	// Bearer token sent with notifications. Supports {env.*}
	// placeholders. Optional.
	NotifyToken string `json:"notify_token,omitempty"`

	// Resolved notify values, kept out of the JSON config so the
	// admin API never exposes them.
	notifyURL   string
	notifyToken string

	whitelist *ipWhitelist
	notifier  *notifier
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

	if t.NotifyURL != "" {
		repl := caddy.NewReplacer()
		t.notifyURL = repl.ReplaceKnown(t.NotifyURL, "")
		t.notifyToken = repl.ReplaceKnown(t.NotifyToken, "")
		t.notifier = newNotifier(t.notifyURL, t.notifyToken, t.logger)
		t.notifier.start(ctx)
	}

	return nil
}

// Validate ensures that all required fields are configured.
func (t *Trigger) Validate() error {
	if len(t.MatchPaths) == 0 {
		return fmt.Errorf("match_path is required")
	}
	if t.MatchStatus == 0 {
		return fmt.Errorf("match_status is required")
	}
	if t.TTL == 0 {
		return fmt.Errorf("ttl is required")
	}
	if t.NotifyToken != "" && t.NotifyURL == "" {
		return fmt.Errorf("notify_token requires notify_url")
	}
	if t.NotifyURL != "" {
		if err := validateNotifyURL(t.notifyURL); err != nil {
			return err
		}
		if strings.ContainsAny(t.notifyToken, "\r\n") {
			return fmt.Errorf("notify_token must not contain newlines")
		}
	}
	return nil
}

// Cleanup stops the notifier and decrements the reference count on the
// shared whitelist.
func (t *Trigger) Cleanup() error {
	if t.notifier != nil {
		t.notifier.stop()
	}
	_, _ = store.Delete(storeKey)
	return nil
}

// ServeHTTP intercepts responses to the configured paths. If the upstream
// returns the expected status code, the client IP is added to the whitelist.
// For non-matching paths, requests pass through without overhead.
func (t *Trigger) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !slices.Contains(t.MatchPaths, r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	rec := &statusRecorder{ResponseWriterWrapper: caddyhttp.ResponseWriterWrapper{ResponseWriter: w}}
	err := next.ServeHTTP(rec, r)

	if rec.status == t.MatchStatus {
		ip := clientIP(r)
		ttl := time.Duration(t.TTL)
		if !t.whitelist.Add(ip, ttl) {
			t.logger.Debug("ip whitelist refreshed", zap.String("ip", ip), zap.Duration("ttl", ttl))
			return err
		}
		t.logger.Info("ip whitelisted", zap.String("ip", ip), zap.Duration("ttl", ttl))
		if t.notifier != nil {
			t.notify(ip, ttl)
		}
	}

	return err
}

// notify queues a notification for a newly whitelisted IP. Only a parsed
// IP goes into the message, never a raw request value.
func (t *Trigger) notify(ip string, ttl time.Duration) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	if !t.notifier.enqueue(fmt.Sprintf("%s whitelisted for %s", addr, ttl)) {
		t.logger.Debug("notification dropped, queue full")
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (t *Trigger) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "match_path":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				t.MatchPaths = append(t.MatchPaths, args...)
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
			case "notify_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.NotifyURL = d.Val()
			case "notify_token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				t.NotifyToken = d.Val()
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

// WriteHeader captures the final (non-1xx) status code and delegates to the
// wrapped writer.
func (r *statusRecorder) WriteHeader(code int) {
	if code >= 200 && r.status == 0 {
		r.status = code
	}
	r.ResponseWriterWrapper.WriteHeader(code)
}

// Write records an implicit 200 if WriteHeader was not called.
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriterWrapper.Write(b)
}

// ReadFrom records an implicit 200 if WriteHeader was not called.
func (r *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriterWrapper.ReadFrom(src)
}

var (
	_ caddyhttp.MiddlewareHandler = (*Trigger)(nil)
	_ caddy.Provisioner           = (*Trigger)(nil)
	_ caddy.Validator             = (*Trigger)(nil)
	_ caddy.CleanerUpper          = (*Trigger)(nil)
	_ caddyfile.Unmarshaler       = (*Trigger)(nil)
)
