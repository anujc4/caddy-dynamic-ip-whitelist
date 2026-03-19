package ipgate

import (
	"testing"
	"time"
)

func TestIPWhitelist_AddAndCheck(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Hour)

	if !w.IsAllowed("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be allowed")
	}
	if w.IsAllowed("5.6.7.8") {
		t.Error("expected 5.6.7.8 to not be allowed")
	}
}

func TestIPWhitelist_Expiry(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	if w.IsAllowed("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be expired")
	}
}

func TestIPWhitelist_Sweep(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Millisecond)
	w.Add("5.6.7.8", 1*time.Hour)

	time.Sleep(5 * time.Millisecond)

	pruned := w.Sweep()
	if pruned != 1 {
		t.Errorf("expected 1 pruned, got %d", pruned)
	}
	if w.Count() != 1 {
		t.Errorf("expected 1 remaining, got %d", w.Count())
	}
	if !w.IsAllowed("5.6.7.8") {
		t.Error("expected 5.6.7.8 to still be allowed")
	}
}

func TestIPWhitelist_Overwrite(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Millisecond)
	w.Add("1.2.3.4", 1*time.Hour)

	time.Sleep(5 * time.Millisecond)

	if !w.IsAllowed("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be allowed after TTL refresh")
	}
}

func TestIPWhitelist_Delete(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Hour)

	if !w.Delete("1.2.3.4") {
		t.Error("expected Delete to return true for existing IP")
	}
	if w.IsAllowed("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be removed")
	}
	if w.Delete("1.2.3.4") {
		t.Error("expected Delete to return false for non-existing IP")
	}
}

func TestIPWhitelist_Clear(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Hour)
	w.Add("5.6.7.8", 1*time.Hour)

	removed := w.Clear()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if w.Count() != 0 {
		t.Errorf("expected 0 remaining, got %d", w.Count())
	}
}

func TestIPWhitelist_Entries(t *testing.T) {
	w := newIPWhitelist()
	w.Add("1.2.3.4", 1*time.Hour)
	w.Add("5.6.7.8", 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	entries := w.Entries()
	if len(entries) != 1 {
		t.Errorf("expected 1 active entry, got %d", len(entries))
	}
	if _, ok := entries["1.2.3.4"]; !ok {
		t.Error("expected 1.2.3.4 in entries")
	}
}

func TestIPWhitelist_Count(t *testing.T) {
	w := newIPWhitelist()
	if w.Count() != 0 {
		t.Errorf("expected 0, got %d", w.Count())
	}
	w.Add("1.2.3.4", 1*time.Hour)
	w.Add("5.6.7.8", 1*time.Hour)
	if w.Count() != 2 {
		t.Errorf("expected 2, got %d", w.Count())
	}
}
