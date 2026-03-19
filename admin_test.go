package ipgate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdmin_ListWhitelist(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("1.2.3.4", 1*time.Hour)
	wl.Add("5.6.7.8", 1*time.Hour)
	a := &Admin{whitelist: wl}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ipgate/whitelist", nil)

	err := a.handleWhitelist(w, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp whitelistResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("expected count 2, got %d", resp.Count)
	}
}

func TestAdmin_ListWhitelist_ExcludesExpired(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("1.2.3.4", 1*time.Hour)
	wl.Add("5.6.7.8", 1*time.Millisecond)
	a := &Admin{whitelist: wl}

	time.Sleep(5 * time.Millisecond)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ipgate/whitelist", nil)

	if err := a.handleWhitelist(w, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp whitelistResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("expected count 1, got %d", resp.Count)
	}
}

func TestAdmin_DeleteAll(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("1.2.3.4", 1*time.Hour)
	wl.Add("5.6.7.8", 1*time.Hour)
	a := &Admin{whitelist: wl}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/ipgate/whitelist", nil)

	if err := a.handleWhitelist(w, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp map[string]int
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["removed"] != 2 {
		t.Errorf("expected 2 removed, got %d", resp["removed"])
	}
	if wl.Count() != 0 {
		t.Errorf("expected empty whitelist, got %d", wl.Count())
	}
}

func TestAdmin_DeleteSingleIP(t *testing.T) {
	wl := newIPWhitelist()
	wl.Add("1.2.3.4", 1*time.Hour)
	wl.Add("5.6.7.8", 1*time.Hour)
	a := &Admin{whitelist: wl}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/ipgate/whitelist/1.2.3.4", nil)

	if err := a.handleWhitelistIP(w, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["deleted"] != "1.2.3.4" {
		t.Errorf("expected deleted 1.2.3.4, got %s", resp["deleted"])
	}
	if wl.IsAllowed("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be removed")
	}
	if !wl.IsAllowed("5.6.7.8") {
		t.Error("expected 5.6.7.8 to still be allowed")
	}
}

func TestAdmin_DeleteSingleIP_NotFound(t *testing.T) {
	wl := newIPWhitelist()
	a := &Admin{whitelist: wl}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/ipgate/whitelist/9.9.9.9", nil)

	err := a.handleWhitelistIP(w, r)
	if err == nil {
		t.Fatal("expected error for non-existing IP")
	}
}
