package ipgate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type notifyRequest struct {
	header http.Header
	body   string
}

// notifyServer returns a test server that forwards every request it
// receives on the returned channel.
func notifyServer(t *testing.T) (*httptest.Server, chan notifyRequest) {
	t.Helper()
	reqs := make(chan notifyRequest, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		reqs <- notifyRequest{header: r.Header.Clone(), body: string(body)}
	}))
	t.Cleanup(srv.Close)
	return srv, reqs
}

func newNotifyTrigger(t *testing.T, url, token string) *Trigger {
	t.Helper()
	n := newNotifier(url, token, zap.NewNop())
	n.start(context.Background())
	t.Cleanup(n.stop)
	return &Trigger{
		MatchPaths:  []string{"/auth/callback"},
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		whitelist:   newIPWhitelist(),
		notifier:    n,
		logger:      zap.NewNop(),
	}
}

func serveFrom(t *testing.T, trigger *Trigger, ip string) {
	t.Helper()
	r, _ := http.NewRequest("POST", "http://example.com/auth/callback", nil)
	r.RemoteAddr = ip + ":12345"
	if err := trigger.ServeHTTP(httptest.NewRecorder(), r, stubHandler{status: 200}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTrigger_NotifiesOnlyNewIP(t *testing.T) {
	srv, reqs := notifyServer(t)
	trigger := newNotifyTrigger(t, srv.URL, "")

	serveFrom(t, trigger, "10.0.0.1")
	serveFrom(t, trigger, "10.0.0.1")

	select {
	case req := <-reqs:
		if req.body != "10.0.0.1 whitelisted for 1h0m0s" {
			t.Errorf("unexpected body %q", req.body)
		}
		if req.header.Get("Title") != "ipgate" || req.header.Get("Tags") != "unlock" {
			t.Errorf("unexpected headers %v", req.header)
		}
		if req.header.Get("Authorization") != "" {
			t.Error("expected no Authorization header without a token")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a notification for a new IP")
	}

	select {
	case <-reqs:
		t.Error("expected no notification on refresh")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTrigger_NotifySendsToken(t *testing.T) {
	srv, reqs := notifyServer(t)
	trigger := newNotifyTrigger(t, srv.URL, "secret")

	serveFrom(t, trigger, "10.0.0.1")

	select {
	case req := <-reqs:
		if got := req.header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("expected bearer token, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a notification")
	}
}

func TestTrigger_SlowNotifyServerDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	trigger := newNotifyTrigger(t, srv.URL, "")

	start := time.Now()
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		serveFrom(t, trigger, ip)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("expected ServeHTTP to not wait on the notify server, took %v", elapsed)
	}
}

func TestNotifier_DropsWhenQueueFull(t *testing.T) {
	n := newNotifier("http://127.0.0.1", "", zap.NewNop())

	for i := 0; i < notifyQueueSize; i++ {
		if !n.enqueue("msg") {
			t.Fatalf("expected enqueue %d to succeed", i)
		}
	}

	done := make(chan bool)
	go func() { done <- n.enqueue("msg") }()
	select {
	case ok := <-done:
		if ok {
			t.Error("expected enqueue on a full queue to drop")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue blocked on a full queue")
	}
}

func TestNotifier_DoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Add(1)
	}))
	t.Cleanup(target.Close)
	hit := make(chan struct{}, 1)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	n := newNotifier(redirect.URL, "", zap.NewNop())
	n.send(context.Background(), "msg")

	select {
	case <-hit:
	default:
		t.Fatal("expected the notify URL to be called")
	}
	if followed.Load() != 0 {
		t.Error("expected redirect to not be followed")
	}
}

func TestNotifier_RateCap(t *testing.T) {
	srv, reqs := notifyServer(t)
	n := newNotifier(srv.URL, "", zap.NewNop())
	n.limiter = rate.NewLimiter(rate.Every(time.Hour), 2)
	n.start(context.Background())
	t.Cleanup(n.stop)

	for i := 0; i < 5; i++ {
		n.enqueue("msg")
	}

	for i := 0; i < 2; i++ {
		select {
		case <-reqs:
		case <-time.After(2 * time.Second):
			t.Fatalf("expected notification %d", i)
		}
	}
	select {
	case <-reqs:
		t.Error("expected notifications over the rate cap to be dropped")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestNotifier_StopEndsWorker(t *testing.T) {
	n := newNotifier("http://127.0.0.1", "", zap.NewNop())
	n.start(context.Background())

	stopped := make(chan struct{})
	go func() {
		n.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("expected stop to end the worker")
	}
}

func TestValidateNotifyURL(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://ntfy.sh/topic", true},
		{"http://ntfy.local:8080/topic", true},
		{"", false},
		{"ntfy.sh/topic", false},
		{"/topic", false},
		{"ftp://ntfy.sh/topic", false},
		{"https:///topic", false},
	}
	for _, tt := range tests {
		err := validateNotifyURL(tt.url)
		if (err == nil) != tt.valid {
			t.Errorf("validateNotifyURL(%q): expected valid=%v, got err=%v", tt.url, tt.valid, err)
		}
		if err != nil && tt.url != "" && strings.Contains(err.Error(), tt.url) {
			t.Errorf("validateNotifyURL(%q): error must not contain the URL", tt.url)
		}
	}
}

func TestTrigger_ProvisionResolvesNotifyEnv(t *testing.T) {
	t.Setenv("IPGATE_TEST_NTFY_URL", "https://ntfy.sh/secret-topic")
	t.Setenv("IPGATE_TEST_NTFY_TOKEN", "secret-token")

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	trigger := &Trigger{
		MatchPaths:  []string{"/auth/callback"},
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		NotifyURL:   "{env.IPGATE_TEST_NTFY_URL}",
		NotifyToken: "{env.IPGATE_TEST_NTFY_TOKEN}",
	}
	if err := trigger.Provision(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = trigger.Cleanup() }()
	if err := trigger.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if trigger.notifyURL != "https://ntfy.sh/secret-topic" || trigger.notifyToken != "secret-token" {
		t.Error("expected env placeholders to be resolved")
	}
	cfg, _ := json.Marshal(trigger)
	if strings.Contains(string(cfg), "secret") {
		t.Errorf("expected JSON config to keep placeholders, got %s", cfg)
	}
}

func TestTrigger_ValidateRejectsTokenWithoutURL(t *testing.T) {
	trigger := &Trigger{
		MatchPaths:  []string{"/auth/callback"},
		MatchStatus: 200,
		TTL:         caddy.Duration(1 * time.Hour),
		NotifyToken: "secret",
	}
	if err := trigger.Validate(); err == nil {
		t.Error("expected notify_token without notify_url to fail validation")
	}
}

func TestTrigger_UnmarshalCaddyfileNotify(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ipgate_trigger {
		match_path /auth/callback
		match_status 200
		ttl 4h
		notify_url {env.IPGATE_NTFY_URL}
		notify_token {env.IPGATE_NTFY_TOKEN}
	}`)

	var trigger Trigger
	if err := trigger.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if trigger.NotifyURL != "{env.IPGATE_NTFY_URL}" || trigger.NotifyToken != "{env.IPGATE_NTFY_TOKEN}" {
		t.Errorf("unexpected notify config: %q %q", trigger.NotifyURL, trigger.NotifyToken)
	}
}

func BenchmarkTrigger_ServeHTTP(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	newTrigger := func(withNotifier bool) *Trigger {
		trigger := &Trigger{
			MatchPaths:  []string{"/auth/callback", "/api/me"},
			MatchStatus: 200,
			TTL:         caddy.Duration(1 * time.Hour),
			whitelist:   newIPWhitelist(),
			logger:      zap.NewNop(),
		}
		if withNotifier {
			trigger.notifier = newNotifier(srv.URL, "", zap.NewNop())
			trigger.notifier.start(context.Background())
			b.Cleanup(trigger.notifier.stop)
		}
		return trigger
	}

	cases := []struct {
		name string
		path string
	}{
		{"non_matching", "/other"},
		{"refresh", "/api/me"},
	}
	for _, tc := range cases {
		for _, withNotifier := range []bool{false, true} {
			name := tc.name + "/no_notifier"
			if withNotifier {
				name = tc.name + "/notifier"
			}
			b.Run(name, func(b *testing.B) {
				trigger := newTrigger(withNotifier)
				r, _ := http.NewRequest("GET", "http://example.com"+tc.path, nil)
				r.RemoteAddr = "10.0.0.1:12345"
				w := httptest.NewRecorder()
				b.ReportAllocs()
				for b.Loop() {
					_ = trigger.ServeHTTP(w, r, stubHandler{status: 200})
				}
			})
		}
	}
}
