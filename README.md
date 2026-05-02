# Headscale Panel

Web admin panel for [Headscale](https://github.com/juanfont/headscale).

---

## Contents

- [Headscale Panel](#headscale-panel)
  - [Contents](#contents)
  - [Installation](#installation)
  - [Configuration](#configuration)
    - [`.env`](#env)
    - [`config/config.yaml`](#configconfigyaml)
    - [Precedence](#precedence)
  - [First login \& MFA](#first-login--mfa)
  - [Pages](#pages)
    - [Dashboard](#dashboard)
    - [Users](#users)
    - [Nodes](#nodes)
    - [Preauth keys](#preauth-keys)
    - [Policy](#policy)
    - [DNS](#dns)
    - [Diagnostics → Route lookup](#diagnostics--route-lookup)
    - [Diagnostics → Policy test](#diagnostics--policy-test)
    - [Settings](#settings)
    - [Account](#account)
  - [Direct-DB bypass operations](#direct-db-bypass-operations)
  - [Container restarts](#container-restarts)
  - [Public / TLS deployment](#public--tls-deployment)
  - [Building from source](#building-from-source)
  - [License](#license)

---

## Installation

You only need three files from the repo to deploy: `compose.yaml`, `.env.example`, and `config/config.yaml.example`. The default `compose.yaml` pulls the published panel image — you don't need to clone the source or build anything locally.

```bash
mkdir -p headscale-panel/config && cd headscale-panel
BASE=https://raw.githubusercontent.com/TinyHomeLab-io/headscale-panel/main
curl -fsSL $BASE/compose.yaml              -o compose.yaml
curl -fsSL $BASE/.env.example              -o .env
curl -fsSL $BASE/config/config.yaml.example -o config/config.yaml
```

Edit `.env` and `config/config.yaml` (see [Configuration](#configuration)).

Boot Headscale alone first to mint a panel API key:

```bash
docker compose up -d headscale
docker exec headscale headscale apikeys create --expiration 99y
```

Copy the `hskey-api-…` output into `PANEL_HEADSCALE_API_KEY` in `.env`, then bring up the panel:

```bash
docker compose up -d
```

This pulls `ghcr.io/tinyhomelab-io/headscale-panel:latest` for the panel service. The image is fully self-contained — no source bind-mount needed.

The panel listens on port `8080`. Open <http://localhost:8080>.

The example `compose.yaml` maps `8080:8080` (panel reachable on every host interface). To restrict it to loopback, change to `"127.0.0.1:8080:8080"`. To remap if 8080 is taken on the host, change to `"<your-port>:8080"` — the container always serves on internal port 8080. For internet exposure, front it with a TLS-terminating reverse proxy (login + TOTP otherwise go in cleartext).

To pin a specific version, edit `compose.yaml` and replace `:latest` with a calendar tag (e.g. `:2026.05.02`).

---

## Configuration

### `.env`

Static infrastructure settings that don't change at runtime. Edit manually; the panel does not write here.

| Variable | Required | Default | Notes |
|---|---|---|---|
| `HEADSCALE_LISTEN_ADDR` | yes | `0.0.0.0:8080` | Headscale's HTTP listener |
| `HEADSCALE_METRICS_LISTEN_ADDR` | yes | `127.0.0.1:9090` | Prometheus metrics |
| `HEADSCALE_GRPC_LISTEN_ADDR` | yes | `127.0.0.1:50443` | gRPC listener |
| `HEADSCALE_PREFIXES_V4` | yes | `100.64.0.0/10` | Tailnet IPv4 pool |
| `HEADSCALE_PREFIXES_V6` | yes | `fd7a:115c:a1e0::/48` | Tailnet IPv6 pool |
| `HEADSCALE_DATABASE_TYPE` | yes | `sqlite` | `sqlite` or `postgres` |
| `HEADSCALE_DATABASE_SQLITE_PATH` | sqlite | `/var/lib/headscale/db.sqlite` | DB file inside the container |
| `HEADSCALE_NOISE_PRIVATE_KEY_PATH` | yes | `/var/lib/headscale/noise_private.key` | Crypto identity, persists across restarts |
| `HEADSCALE_POLICY_MODE` | yes | `database` | Stores ACL policy in the DB; the panel relies on this |
| `HEADSCALE_DERP_*` | yes | (Tailscale public) | DERP relay config |
| `HEADSCALE_LOG_LEVEL` | no | `info` | |
| `PANEL_HEADSCALE_URL` | yes | `http://headscale:8080` | URL the panel uses to reach Headscale (Docker network DNS) |
| `PANEL_HEADSCALE_VERIFY_TLS` | no | `true` | Set `false` when the URL above doesn't match Headscale's cert (e.g. `https://localhost` while the cert is for a public hostname) |
| `PANEL_HEADSCALE_CONTAINER` | yes | `headscale` | Container name to restart after direct-DB writes |
| `PANEL_HEADSCALE_API_KEY` | **yes** | — | Mint via `headscale apikeys create`; required for the panel to talk to Headscale |
| `PANEL_BOOTSTRAP_USER` | first-run | `admin` | Created on first start if no panel users exist |
| `PANEL_BOOTSTRAP_PASSWORD` | first-run | — | Set to something strong, then remove after first login |
| `PANEL_DB_PATH` | yes | `/data/panel.sqlite` | Panel's own users / sessions DB |
| `PANEL_TOTP_ISSUER` | no | `Headscale Panel` | Shown in authenticator apps |
| `PANEL_SESSION_LIFETIME_SECS` | no | `86400` | 24 hours |
| `PANEL_SECURE_COOKIES` | no | `false` | Set `true` when serving over HTTPS |

### `config/config.yaml`

Runtime-tunable settings. Edited via the panel UI (Settings, DNS pages); you can also hand-edit. Saving from the UI restarts Headscale.

Common fields:

```yaml
server_url: https://headscale.example.com   # what Tailscale clients connect to

dns:
  magic_dns: true
  base_domain: ts.example.com
  override_local_dns: false
  nameservers:
    global: [1.1.1.1, 1.0.0.1]
    split: {}                # domain → [server,…]
  search_domains: []
  extra_records: []          # [{name, type, value}, …]

# TLS — leave unset for HTTP
tls_letsencrypt_hostname: ""
tls_cert_path: ""
tls_key_path: ""
```

Anything in Headscale's [config reference](https://headscale.net/stable/ref/configuration/) is valid here. The Settings page has a raw YAML editor for fields the structured forms don't cover.

### Precedence

When `.env` and `config.yaml` both define a key, **`.env` wins** (Headscale uses Viper; environment variables override the config file).

That's why DNS / `server_url` / TLS env vars are deliberately *not* in `.env.example` — leaving them unset lets the panel manage those keys in `config.yaml`. Don't add them back to `.env` unless you intend to override the panel.

---

## First login & MFA

1. Open <http://localhost:8080>.
2. Log in with the bootstrap user (`admin` / your `PANEL_BOOTSTRAP_PASSWORD`).
3. The panel forces TOTP enrollment on first login: scan the QR code with an authenticator app (1Password, Authy, Aegis, etc.), enter the 6-digit code.
4. Subsequent logins prompt for username + password, then the TOTP code.
5. **After first login, remove `PANEL_BOOTSTRAP_PASSWORD` from `.env`.** The bootstrap is idempotent — it only seeds when zero panel users exist — so removing the line is safe and keeps a stale credential off disk.

Sessions are server-side (stored in `panel-data/panel.sqlite`). The session cookie holds only an opaque ID. Logging out invalidates it. Changing your password invalidates all *other* sessions for the account.

---

## Pages

### Dashboard

Overview cards (users, nodes, exit nodes, subnet routers, approved routes, active preauth keys), donut chart for online/offline node split, IPv4 + IPv6 allocation summaries, a "Recent activity" table of the five most recently seen nodes.

### Users

Headscale user accounts. Create, rename (modal), delete (only if the user has no nodes — Headscale rejects otherwise).

### Nodes

List of registered machines. Per-row actions:

- **Manage** — opens the detail page
- **Rename** — in-page modal
- **Expire** — kicks the node off the tailnet; it must re-authenticate
- **Delete** — removes the node entirely

Top-of-page **+ Register a node** wizard:

- Step 1 builds the registration command. Pick options (preauth key, hostname, advertise routes, exit node, accept routes/DNS, Tailscale SSH, shields-up, operator). Output format is **Native** (`tailscale up`), **Docker run**, or **Docker Compose**. The "+ New key" button creates a single-use 24h preauth key for the selected user and inserts it into the field.
- Step 2 (only needed without a preauth key): paste the 24-character registration ID Tailscale prints, pick a user, click Register.

Node detail page (`/nodes/<id>`):

- Overview (ID, hostname, user, IPs, MagicDNS, status, machine + node keys — all click-to-copy)
- Rename
- Routes — checkboxes for each advertised subnet route plus a separate "Use as exit node" toggle. Approved-but-no-longer-advertised routes are flagged in amber.
- IP addresses (advanced) — direct-DB edit with prefix + uniqueness validation
- Tags — chips with × to remove individually, an "Add tag" input. If you add a tag that hasn't been declared in the policy yet, the panel auto-declares it in `tagOwners` using the node's owner as the new tag owner, then applies the tag.
- Change user (advanced) — direct-DB reassignment

### Preauth keys

Create keys (user dropdown, expiration preset, reusable / ephemeral toggles), expire keys, delete keys. Newly-created keys are shown once in a flash banner — copy immediately, the API masks them on subsequent reads.

### Policy

Firewall-style ACL editor.

- **Rules** — table with #, Action (accept/drop pill), Source, Destination, Proto, Ports, and per-row ✎/↑/↓/× actions. ✎ opens a modal that edits the rule in place. Drag the `⋮⋮` handle to reorder; ↑/↓ buttons work as a touch-friendly fallback. Add-rule form below the table; protocols that don't carry ports (ICMP, IGMP, GRE, ESP, AH) automatically hide the ports field. Source / destination autocomplete includes Tailscale autogroups (`autogroup:self` for "each user → their own nodes", `autogroup:internet` for exit-node traffic).
- **Tag owners** — declare tags before nodes can use them. Each row has chips per owner with × to remove, plus an inline "add owner" form. Owner inputs autocomplete from the current users + groups. Adding a tag from a node's detail page also auto-declares it here using that node's owner.

Saves write back to the policy via Headscale's API. The policy lives in the DB (because `HEADSCALE_POLICY_MODE=database`), so no file edits.

> Headscale's policy API requires `HEADSCALE_POLICY_MODE=database`. If it's set to `file` (the Headscale default), all policy writes are rejected with `update is disabled for modes other than 'database'`. Headscale 0.28 also returns HTTP 500 on `GET /api/v1/policy` when database mode is on but no policy has been written yet (`acl policy not found`); the panel handles this gracefully and shows the default policy.

### DNS

Manages the `dns:` block of `config.yaml`.

- MagicDNS toggle, base domain
- Global nameservers (one per line) — used for split-DNS / search-domain / MagicDNS lookups
- "Override local DNS" — when on, clients route *all* DNS queries through the global nameservers (otherwise they only consult those for matching domains)
- Search domains
- Split DNS — domain → list of nameservers (add/remove rows)
- Custom records — A / AAAA only (Headscale's `extra_records` doesn't push CNAME or wildcard records to clients — see [headscale#2508](https://github.com/juanfont/headscale/issues/2508)). Value field autocompletes node IPs. Any pre-existing CNAME / wildcard rows in `config.yaml` are flagged as inert and stripped on save.

Saving rewrites `config.yaml` and restarts Headscale.

### Diagnostics → Route lookup

Find which nodes carry a destination.

- CIDR (e.g. `10.0.0.0/24`) → exact-match advertised/approved subnet routes
- Single IP (e.g. `192.168.1.5`) → covering route, *or* a node's own tailnet IP
- `0.0.0.0/0` / `::/0` → exit nodes
- Anything that doesn't match → falls back to the available exit nodes with a note that traffic only routes that way for clients which have selected an exit node via `tailscale up --exit-node=…`

### Diagnostics → Policy test

Walks the ACL rules with an identity-expansion model:

- Source / destination accept users (`user1@`), tags (`tag:server`), groups, hosts, IPs, CIDRs, or `*`
- Group recursion, user→IP expansion, tag→IP expansion, IP-in-CIDR matching all happen against current node state
- Result: ALLOW / DROP (with the matched rule index, src/dst entries, port spec) or DENY (no rule matched — Tailscale's implicit deny)
- "Show matching rule →" jumps to `/policy` and flashes the matched row

### Settings

- **Server** — `server_url` (the URL Tailscale clients use to reach Headscale)
- **TLS** — None / Let's Encrypt (auto-issue, requires public DNS + reachable challenge port) / Manual cert (paths to files inside the bind-mounted `data/` directory)
- **Raw YAML editor** (advanced) — direct edit of the entire `config.yaml`. Validates as YAML before saving.

Saving any of these restarts Headscale.

### Account

- Change password (current + new, min 12 chars, argon2id hashed). On change, all *other* sessions for the account are invalidated; current session stays.
- Reset 2FA (requires current password) — clears the TOTP secret, ends all sessions, forces re-enrollment on next login.

---

## Direct-DB bypass operations

Headscale's API doesn't cover every operation. The panel writes directly to `data/db.sqlite` for:

| Operation | Reason for bypass |
|---|---|
| Edit a node's IPs (`nodes.ipv4`, `nodes.ipv6`) | No API endpoint |
| Reassign a node to a different user (`nodes.user_id`) | No API endpoint |
| Remove the last tag (`tags='[]'`) | API rejects empty tag lists |
| Clear all approved routes (`approved_routes='[]'`) | API returns 200 but doesn't persist empty lists |

Each bypass triggers a Headscale container restart so the in-memory state reloads from the modified DB.

---

## Container restarts

Anything that requires Headscale to reload — the bypass ops above, plus saves on the Settings and DNS pages — restarts the Headscale container via the bind-mounted Docker socket and waits for `/health` to come back. Typically 5–10 seconds. The panel polls and only redirects you to a working page once Headscale is responsive.

The panel itself runs independently of Headscale; restarting Headscale doesn't restart the panel.

---

## Public / TLS deployment

The panel listens on port `8080` and the example compose binds it on all host interfaces — don't expose it to the internet directly. Front it with a TLS-terminating reverse proxy (Caddy, Traefik, nginx). Once the panel is served over HTTPS, set:

```
PANEL_SECURE_COOKIES=true
```

For Headscale itself, configure TLS via the Settings page. Two modes:

- **Let's Encrypt** — Headscale handles ACME directly. Requires a public DNS record pointing at your server and the chosen challenge port (HTTP-01 → 80, TLS-ALPN-01 → 443) reachable from the internet. You'll also need to expose 80/443 in `compose.yaml`.
- **Manual certificate** — point `tls_cert_path` and `tls_key_path` at files inside `data/` (mounted to `/var/lib/headscale/` in the container).

Note that enabling TLS doesn't change `listen_addr` automatically; you may also want to set `HEADSCALE_LISTEN_ADDR=0.0.0.0:443` in `.env` and expose 443 in `compose.yaml`.

---

## Building from source

For development, customisation, or running without depending on the published image, see [BUILD.md](./BUILD.md). It covers switching `compose.yaml` to local-build mode, producing tagged images, and the release flow.

---

## License

[BSD 3-Clause](./LICENSE).
