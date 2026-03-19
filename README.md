# caddy-dynamic-ip-whitelist

A Caddy module to dynamically whitelist IPs based on your auth provider. Whitelisted IPs are stored in-memory. I intentionally did not use an external database since my personal use-case is small and storing a few thousand IPs in memory should be fine.

## How it works

Two Caddy modules share an in-memory IP whitelist:

- **`ipgate_trigger`** (handler) — watches upstream responses on a configured path. When the response status matches, the client IP is whitelisted with a TTL.
- **`ipgate`** (matcher) — returns true if the client IP is in the whitelist.

```plaintext
User authenticates via browser
  -> ipgate_trigger sees 200 on /api/auth/login
  -> IP whitelisted for an arbitrary time

User (or any device on that IP) hits a service
  -> @allowed ipgate matcher checks whitelist
  -> if allowed -> reverse_proxy to backend
  -> if denied  -> 403
```

## Build

```bash
xcaddy build --with github.com/anujc4/caddy-dynamic-ip-whitelist
```

## Caddyfile

```caddy
{
    order ipgate_trigger before reverse_proxy
}

# Auth endpoint — trigger whitelists IP on successful login
auth.example.com {
    ipgate_trigger {
        match_path   /api/webauthn/login/finish
        match_status 200
        ttl          4h
        sweep_interval 1m  # optional, default 1m
    }

    reverse_proxy auth-backend:8080
}

# Protected service — only whitelisted IPs can access
app.example.com {
    @allowed ipgate
    handle @allowed {
        reverse_proxy app-backend:3000
    }
    handle {
        respond "Forbidden" 403
    }
}
```

## Configuration

### ipgate_trigger

| Directive        | Required | Description                                       |
| ---------------- | -------- | ------------------------------------------------- |
| `match_path`     | yes      | Request path that signals successful auth         |
| `match_status`   | yes      | HTTP status code confirming auth success          |
| `ttl`            | yes      | Duration to whitelist the IP (e.g. `4h`, `30m`)   |
| `sweep_interval` | no       | How often to prune expired entries (default `1m`) |

### ipgate (matcher)

No configuration. Matches if the client IP is in the whitelist.

```caddy
@allowed ipgate
```

## Admin API

Endpoints are available on Caddy's [admin API](https://caddyserver.com/docs/api) (default `localhost:2019`).

### List all whitelisted IPs

```bash
curl localhost:2019/ipgate/whitelist
```

```json
{
  "count": 1,
  "entries": [
    {"ip": "127.0.0.1", "expires": "2026-03-19T22:00:00Z"}
  ]
}
```

### Remove a single IP

```bash
curl -X DELETE localhost:2019/ipgate/whitelist/127.0.0.1
```

### Remove all IPs

```bash
curl -X DELETE localhost:2019/ipgate/whitelist
```
