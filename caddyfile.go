package ipgate

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("ipgate_trigger", parseTriggerCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("ipgate_trigger", httpcaddyfile.Before, "reverse_proxy")
}

func parseTriggerCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var t Trigger
	err := t.UnmarshalCaddyfile(h.Dispenser)
	return &t, err
}
