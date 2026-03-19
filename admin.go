package ipgate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Admin{})
}

// Admin provides admin API endpoints for managing the IP whitelist.
//
// Endpoints:
//
//	GET    /ipgate/whitelist      — list all whitelisted IPs
//	DELETE /ipgate/whitelist      — remove all whitelisted IPs
//	DELETE /ipgate/whitelist/{ip} — remove a single IP
type Admin struct {
	whitelist *ipWhitelist
}

// CaddyModule returns the Caddy module information.
func (Admin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.ipgate",
		New: func() caddy.Module { return new(Admin) },
	}
}

// Provision loads the shared whitelist from the usage pool.
func (a *Admin) Provision(_ caddy.Context) error {
	wl := newIPWhitelist()
	val, loaded := store.LoadOrStore(storeKey, wl)
	if loaded {
		wl = val.(*ipWhitelist)
	}
	a.whitelist = wl
	return nil
}

// Cleanup decrements the reference count on the shared whitelist.
func (a *Admin) Cleanup() error {
	_, _ = store.Delete(storeKey)
	return nil
}

// Routes returns the admin API routes for the ipgate module.
func (a *Admin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/ipgate/whitelist",
			Handler: caddy.AdminHandlerFunc(a.handleWhitelist),
		},
		{
			Pattern: "/ipgate/whitelist/",
			Handler: caddy.AdminHandlerFunc(a.handleWhitelistIP),
		},
	}
}

type whitelistEntry struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
}

type whitelistResponse struct {
	Count   int              `json:"count"`
	Entries []whitelistEntry `json:"entries"`
}

func (a *Admin) handleWhitelist(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case http.MethodGet:
		entries := a.whitelist.Entries()
		resp := whitelistResponse{
			Count:   len(entries),
			Entries: make([]whitelistEntry, 0, len(entries)),
		}
		for ip, expiry := range entries {
			resp.Entries = append(resp.Entries, whitelistEntry{
				IP:      ip,
				Expires: expiry,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(resp)

	case http.MethodDelete:
		removed := a.whitelist.Clear()
		w.Header().Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(map[string]int{"removed": removed})

	default:
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}
}

func (a *Admin) handleWhitelistIP(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodDelete {
		return caddy.APIError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("method not allowed"),
		}
	}

	ip := strings.TrimPrefix(r.URL.Path, "/ipgate/whitelist/")
	if ip == "" {
		return caddy.APIError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("ip address required"),
		}
	}

	if !a.whitelist.Delete(ip) {
		return caddy.APIError{
			HTTPStatus: http.StatusNotFound,
			Err:        fmt.Errorf("ip %s not found in whitelist", ip),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]string{"deleted": ip})
}

var (
	_ caddy.AdminRouter = (*Admin)(nil)
	_ caddy.Provisioner = (*Admin)(nil)
	_ caddy.CleanerUpper = (*Admin)(nil)
)
