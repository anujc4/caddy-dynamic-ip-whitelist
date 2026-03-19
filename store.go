// Package ipgate implements a Caddy module for IP-based access control.
// Users authenticate once through any auth provider, and their IP is
// whitelisted for a configurable duration. During that time, all services
// are accessible from that IP without further authentication.
package ipgate

import (
	"sync"
	"time"
)

// ipWhitelist is a thread-safe store of IP addresses with expiry times.
type ipWhitelist struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

func newIPWhitelist() *ipWhitelist {
	return &ipWhitelist{
		entries: make(map[string]time.Time),
	}
}

// Add whitelists an IP for the given duration. If the IP already exists,
// its expiry is replaced.
func (w *ipWhitelist) Add(ip string, ttl time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries[ip] = time.Now().Add(ttl)
}

// IsAllowed returns true if the IP is in the whitelist and has not expired.
func (w *ipWhitelist) IsAllowed(ip string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	expiry, ok := w.entries[ip]
	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// Sweep removes all expired entries and returns the number pruned.
func (w *ipWhitelist) Sweep() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	pruned := 0
	for ip, expiry := range w.entries {
		if now.After(expiry) {
			delete(w.entries, ip)
			pruned++
		}
	}
	return pruned
}

// Delete removes a single IP from the whitelist. Returns true if it existed.
func (w *ipWhitelist) Delete(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.entries[ip]
	if ok {
		delete(w.entries, ip)
	}
	return ok
}

// Clear removes all entries from the whitelist and returns the count removed.
func (w *ipWhitelist) Clear() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(w.entries)
	w.entries = make(map[string]time.Time)
	return n
}

// Entries returns a snapshot of all non-expired entries.
func (w *ipWhitelist) Entries() map[string]time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	now := time.Now()
	result := make(map[string]time.Time, len(w.entries))
	for ip, expiry := range w.entries {
		if now.Before(expiry) {
			result[ip] = expiry
		}
	}
	return result
}

// Count returns the total number of entries (including expired).
func (w *ipWhitelist) Count() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.entries)
}
