package ipgate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	notifyQueueSize = 16
	notifyTimeout   = 5 * time.Second
	notifyMaxDrain  = 4 << 10
)

// notifier POSTs plain-text messages to a URL from a single background
// worker. Sends never block the caller: when the queue is full or the
// rate cap is reached, the message is dropped.
type notifier struct {
	url     string
	token   string
	client  *http.Client
	limiter *rate.Limiter
	events  chan string
	logger  *zap.Logger
	cancel  context.CancelFunc
	done    chan struct{}
}

func newNotifier(url, token string, logger *zap.Logger) *notifier {
	return &notifier{
		url:   url,
		token: token,
		client: &http.Client{
			Timeout:   notifyTimeout,
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		limiter: rate.NewLimiter(rate.Every(6*time.Second), 10),
		events:  make(chan string, notifyQueueSize),
		logger:  logger,
		done:    make(chan struct{}),
	}
}

// start runs the worker until stop is called or ctx is done.
func (n *notifier) start(ctx context.Context) {
	ctx, n.cancel = context.WithCancel(ctx)
	go n.run(ctx)
}

// stop cancels the worker and waits for it to exit.
func (n *notifier) stop() {
	n.cancel()
	<-n.done
}

// enqueue queues a message without blocking. Returns false if dropped.
func (n *notifier) enqueue(msg string) bool {
	select {
	case n.events <- msg:
		return true
	default:
		return false
	}
}

func (n *notifier) run(ctx context.Context) {
	defer close(n.done)
	for {
		select {
		case msg := <-n.events:
			if !n.limiter.Allow() {
				n.logger.Debug("notification dropped, rate limited")
				continue
			}
			n.send(ctx, msg)
		case <-ctx.Done():
			return
		}
	}
}

func (n *notifier) send(ctx context.Context, msg string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, strings.NewReader(msg))
	if err != nil {
		n.logger.Warn("notification failed", zap.String("error", "invalid request"))
		return
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", "ipgate")
	req.Header.Set("Tags", "unlock")
	req.Header.Set("Priority", "default")
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		// The error wraps the URL, which holds the secret topic, so only
		// its class is logged.
		n.logger.Warn("notification failed", zap.String("error", errorClass(err)))
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, notifyMaxDrain))
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		n.logger.Warn("notification failed", zap.Int("status", resp.StatusCode))
	}
}

func errorClass(err error) string {
	var uerr *url.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &uerr) && uerr.Timeout():
		return "timeout"
	default:
		return "request failed"
	}
}

// validateNotifyURL requires an absolute http(s) URL with a host. The URL
// is never included in the error since it is a secret.
func validateNotifyURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("notify_url must be an absolute http(s) URL")
	}
	return nil
}
