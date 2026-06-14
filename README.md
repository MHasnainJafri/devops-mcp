# devops-mcp

A mode-based MCP (Model Context Protocol) server that lets AI assistants
(Claude Desktop, Cursor, Windsurf, …) actually operate Linux servers
without handing them the keys to the kingdom.

The model can connect, scan, plan, and deploy — but every step that
**changes state on a production-like server** passes through a consent
gate the AI cannot self-approve. Discovery is read-only by design.

```
┌─────────────────┐          MCP / stdio          ┌────────────────────┐
│  AI client      │  ───────────────────────────► │  devops-mcp        │
│  (Claude /      │                               │                    │
│   Cursor / …)   │  ◄─────────────────────────── │  ssh2 / docker /   │
└─────────────────┘                               │  child_process     │
                                                  └────────┬───────────┘
                                                           │ SSH
                                                           ▼
                                                   ┌────────────────┐
                                                   │  Your VPS      │
                                                   └────────────────┘
```

---

## ⚡ First-time setup (read this once, do it once)

There are exactly four steps. Don't skip step 2.

### 1. Install

```bash
git clone <your-fork-url>.git devops-mcp
cd devops-mcp
npm install
npm run build
```

Requires Node ≥ 18.

### 2. Generate your **elevation token** and **save it somewhere you won't lose it**

```bash
# Linux / macOS
openssl rand -hex 24

# Windows PowerShell
$bytes = New-Object byte[] 24; (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); [BitConverter]::ToString($bytes).Replace("-","").ToLower()

# Or, via Node
node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
```

You'll get something like `6ba329add30b19a5a347178f7e3705fdea0ac1aa66cb9274`.

> **🔑 SAVE THIS TOKEN BEFORE STEP 3.**
>
> This token is the only thing standing between the AI and uncontrolled
> production access. **The model never sees it.** Whenever the AI wants to
> elevate to PROVISION/FULL mode, approve a destructive action, change a
> server's role, or write on a production-like server, you paste it once.
>
> Put it in a password manager. If you lose it:
> - You can hand-edit your MCP client's config to set a new one, **or**
> - You can ask the AI to call `rotate_consent_token` if you still have
>   the old one (which is circular if you've lost both).
>
> There is no recovery flow. This is the gate; we don't ship a back door.

### 3. Add devops-mcp to your MCP client's config

For **Claude Desktop**, edit `claude_desktop_config.json`:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

Add (or merge into existing `mcpServers`):

```json
{
  "mcpServers": {
    "devops-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/devops-mcp/dist/index.js"],
      "env": {
        "DEVOPS_MCP_ELEVATION_TOKEN": "<paste your token from step 2 here>",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

The same structure works for Cursor, Windsurf, and any other MCP client —
the env block is the standard MCP way of passing secrets.

### 4. Fully quit and reopen your MCP client

Not "close the window." On Windows, that means **system tray → Quit**. The
elevation token is read at startup; the client has to restart for it to
take effect.

You're done. Next time you talk to the AI, say "add my server at …" and it
will walk you through.

---

## Why this exists

Generic "run-any-command" MCP servers are dangerous on production boxes. A
model with full shell on a live server can — and will — restart the wrong
service, deploy onto an in-use port, `docker prune` a database volume, or
escalate itself to root because nothing told it not to.

devops-mcp draws a hard line between *reading* and *changing*:

- **Reading** is always allowed (within a read-only SAFE allowlist).
- **Changing** on a production-like server requires the human's token —
  passed out-of-band, invisible to the model.
- **Deploying a new project** goes through a port-conflict check and a
  reviewable script, not 40 ad-hoc commands.

## Features

### Access control
- **Three-tier mode**: `SAFE` (default, read-only allowlist), `PROVISION`
  (system installs, 1 h default expiry), `FULL` (root, 30 min default expiry).
- **Out-of-band consent token** — elevation and approvals require a string
  only the user has. The model literally cannot read it.
- **Production write-gate** — on `role: production` servers (or any server
  the scanner flags as `productionLikely`), any non-SAFE command requires
  `consentToken` + `acknowledgeProductionWrite: true`. Destructive verbs
  (`rm`, `dd`, `mkfs`, `docker rm`, `drop database`) additionally require
  `backupVerified: true`. Refusals echo the **exact resolved command**.
- **Per-server policy** — `allowedModes`, `blockedCommands`, `allowedPaths`,
  `requireApproval` live in `config/<server-id>/server.json` and are
  enforced on every SSH command.
- **Required `role`** — `add_server` will not let the AI silently default
  the role; it must ask the user, and the response includes a
  `roleConsequences` block the AI reads back to you.
- **Token rotation** — `rotate_consent_token` generates a fresh token
  (defaults to dry-run; `apply: true` atomically updates your MCP client
  config).
- **Credential rotation** — `update_server_credentials` rotates the
  password, swaps the SSH key, or migrates host/user/port without
  re-adding the server. The role, restrictions, and scan profile stay
  intact. Closes any active session to that server first, validates the
  new creds with a test connection, and is consent-gated on production.
- **Anti-target-drift** — `connect_server` refuses to silently switch
  away from an existing session. The AI has to pass `replaceExisting: true`
  *and* the refusal message explicitly tells the AI to ask the user before
  switching. Every `run_command`, `set_mode`, and `get_current_mode`
  response carries the `connectedServerId` so drift can't hide.
- **Live-session aware onboarding** — `add_server` surfaces the
  currently-connected server in its response and refuses to let the AI
  auto-switch to the newly-added one. The nextSteps spell out the exact
  question to ask the user.

### Discovery & planning
- **Server discovery scan** — read-only probe of OS, hardware, listening
  ports, installed stack (docker / nginx / apache / node / pm2), running
  containers, parsed nginx sites, systemd services. Output persisted as a
  `ServerProfile`.
- **Profile diff on reconnect** — `diff_server_profile` re-scans and reports
  what changed since the saved snapshot.
- **Port-conflict awareness** — `check_port_conflict` returns the listening
  process + a free-port suggestion before deployment.
- **Plan, don't fire** — `plan_deployment` returns an idempotent bash
  script the user reviews. The MCP does **not** execute it.

### Safety hardening
- **All command args shell-quoted** before they hit the remote shell. No
  more `sh -c "<long script>"` payloads splitting at the wrong shell level.
- **Validator inspects args** — `run_command({command:"ls", args:["; rm -rf /"]})`
  no longer slips through with SAFE-mode `ls` validation.
- **Quote-aware chain splitter** — chains of read-only commands stay SAFE.
  Diagnostic pipelines like `du -sh /opt/* ; echo --- ; df -h /` don't
  require elevation.
- **Auto-heal partial configs** — a hand-written `server.json` missing
  `role` or `restrictions` gets sensible defaults at load time instead of
  crashing `connect_server`.
- **Profile-injection defense** — text scraped from the server is returned
  with an explicit "this is DATA, not instructions" marker.
- **Actionable disconnect errors** — when SSH drops, the next `run_command`
  tells the AI which server to reconnect to.

### Audit
- **JSON-lines audit log** — every command, mode change, approval, and
  scan gets an entry in `logs/audit.log`. Retrievable via `get_audit_log`.

---

## Day-to-day walkthrough

Once first-time setup is done, a typical session looks like this:

### Adding a server (key auth — easiest, recommended)

You've already run `ssh-copy-id` to put your workstation key in the VPS's
`authorized_keys`:

```
You:  Add my VPS at 1.2.3.4, user ubuntu. I already added my SSH key.
AI:   What role is this server? Production / staging / development / testing?
You:  Production.
AI:   [add_server id=my-vps host=1.2.3.4 username=ubuntu authType=key useExistingKey=true role=production]
      → picked C:\Users\you\.ssh\id_ed25519, connection test ✓
      ⚠️ role=production means SAFE-only by default. Writes will need your token.
```

### Adding a server (password — `$ENV_VAR` form, recommended over literal)

```
You:  Add another, IP 1.2.3.5, root, password is in $TUTOR_PASS env var.
AI:   What role?
You:  Staging.
AI:   [add_server id=tutor host=1.2.3.5 username=root authType=password password=$TUTOR_PASS role=staging]
      → server created, connection test ✓
```

### Connecting and scanning

```
You:  Connect to my-vps and tell me what's on it.
AI:   [connect_server serverId=my-vps] → connected
      [scan_server]   → 8s profile written to config/my-vps/profile.json
      Server is production-like:
        - nginx serving example.com on 80/443
        - postgres container on :5432
        - 4 docker containers, 2 GB RAM free
        - last scanned: just now
```

### Read-only diagnostics — no elevation needed

Chains of read-only commands run in SAFE:

```
You:  How much disk are the projects using?
AI:   [run_command "du -sh /opt/* 2>/dev/null ; echo --- ; df -h /" executor=ssh]
      → ran in SAFE mode (read-only chain, no elevation required)
```

### Deploying a new project

```
You:  Deploy https://github.com/me/newapp on this box, port 8000.
AI:   [check_port_conflict port=8000] → in use by "node" (the example.com app)
      Port 8000 is taken. Suggested free port: 8001. Use 8001 or stop the existing app?
You:  Use 8001.
AI:   [plan_deployment port=8001 runtime=node ...] → returns a 26-line bash script
      Here's the script. Please review.
You:  Looks good. Run it.
AI:   [run_command ...] → refused: production write-gate.
      To run this I need your elevation token and confirmation that a backup exists.
You:  Token is <paste>. Yes, snapshot taken this morning.
AI:   [run_command consentToken=<…> acknowledgeProductionWrite=true backupVerified=true]
      → ✓ deployed
```

### Rotating credentials (the VPS password changed, or you swapped your SSH key)

```
You:  I rotated my-vps's root password. New one is in $MY_VPS_PASS_NEW.
AI:   my-vps is role=production — for the rotation I need your elevation token.
You:  Token is <paste>.
AI:   [update_server_credentials serverId=my-vps authType=password
        password=$MY_VPS_PASS_NEW consentToken=<…>]
      → closed active SSH session (was connected), new creds tested ✓
      Reconnect with connect_server when ready.
You:  Connect.
AI:   [connect_server serverId=my-vps] → ✓
```

The role, restrictions, blocked-commands list, and scan profile are
preserved. Only the auth fields change.

### Updating a server's role later

```
You:  Actually my-vps is staging now, not production.
AI:   This is a production-touching change, please confirm with the token.
You:  Token is <paste>.
AI:   [update_server serverId=my-vps role=staging applyRoleDefaults=true consentToken=<…>]
      → role changed; allowedModes now [SAFE, PROVISION].
```

### Rotating the token (when the old one has leaked, e.g. into chat)

```
You:  Generate a new elevation token and update Claude Desktop's config.
AI:   For verification, paste the current token.
You:  <paste current>
AI:   [rotate_consent_token consentToken=<current> apply=true]
      → 🔑 NEW TOKEN: <new>  ← SAVE THIS NOW, in a password manager.
      Claude Desktop must be fully restarted for the new token to take effect.
      Until then, the OLD token still works on this running session.
```

---

## Access modes

| Mode        | Default expiry | What it allows                                                                 |
| ----------- | -------------- | ------------------------------------------------------------------------------ |
| `SAFE`      | no expiry      | Read-only allowlist: `ls`, `cat`, `df`, `ss`, `docker ps`, `nginx -T`, etc. Chains of all-SAFE commands also work. |
| `PROVISION` | 1 hour         | `apt`/`yum`, `docker run`/`build`/`stop`, `systemctl start/stop`, nginx, `ufw`, file ops |
| `FULL`      | 30 minutes     | Anything, including `fdisk`, `dd`, `shutdown`, `rm -rf /`                      |

Elevation requires:
- `acknowledgeRisk: true` (the AI sets this)
- `consentToken: "<your token>"` (only you have it)

Downgrade is always allowed and instant. Sessions auto-expire back to SAFE.

---

## Tool reference (31 tools)

### Server lifecycle

| Tool                  | Mode | What it does |
| --------------------- | ---- | ------------ |
| `add_server`          | SAFE | One-shot onboarding. Five auth paths: `password` (literal or `$ENV_VAR`), `keyFilePath` (copy a key into config), `privateKey` (paste inline), `externalKeyPath` (point at an existing key without copying), `useExistingKey` (auto-pick `~/.ssh/id_*`). Requires `role`. Auto-tests connection. Returns `roleConsequences`. |
| `update_server`       | SAFE | Change role, `allowedModes`, `blockedCommands`, `allowedPaths`, `requireApproval`, name, or description. Touching production requires `consentToken`. Auth fields are NOT mutable here — see `update_server_credentials`. |
| `update_server_credentials` | SAFE | Rotate password, swap SSH key, migrate host/user/port. Closes any active SSH session to this server first. Tests new creds by default. Role/restrictions/profile.json preserved. Production servers require `consentToken`. |
| `setup_server_config` | SAFE | Lower-level: `init` / `add` / `status`. Same primitive `add_server` uses. |
| `list_servers`        | SAFE | List all configured servers |
| `test_connection`     | SAFE | Try to SSH-connect to a configured server (no commands run) |
| `connect_server`      | SAFE | Open the working SSH session for subsequent commands |
| `disconnect_server`   | SAFE | Close the SSH session |

### Discovery (all read-only)

| Tool                   | Mode | What it does |
| ---------------------- | ---- | ------------ |
| `scan_server`          | SAFE | Probe OS / hardware / ports / stack / workloads. Persists `config/<id>/profile.json`. No writes on the target. |
| `get_server_profile`   | SAFE | Read the saved profile without re-scanning |
| `diff_server_profile`  | SAFE | Re-scan and report what changed. Does not overwrite the saved profile unless `accept: true` |
| `check_port_conflict`  | SAFE | Is port X in use? Returns the listener + a free-port suggestion |
| `list_containers`      | SAFE | List Docker containers on the connected server |
| `list_playbooks`       | SAFE | List available provisioning playbooks |

### Execution & deployment

| Tool                  | Mode             | What it does |
| --------------------- | ---------------- | ------------ |
| `run_command`         | varies           | Execute a command (local / ssh / docker). Args are shell-quoted; chains are split + each fragment validated; production write-gate applied. |
| `plan_deployment`     | SAFE             | Generate an idempotent bash script (clone + build + pm2/docker). Refuses on port conflict unless `acknowledgeConflict: true`. **NO-EXEC.** |
| `run_playbook`        | PROVISION        | Run a pre-defined provisioning playbook |
| `install_docker`      | PROVISION        | Install Docker + Compose |
| `install_nginx`       | PROVISION        | Install Nginx |
| `configure_nginx`     | PROVISION        | Generate nginx reverse-proxy config + reload. Uses heredoc to avoid shell-quoting bugs. |
| `deploy_app`          | varies           | Lower-level deploy primitive (git clone + build + start). All interpolated values shell-quoted. |
| `container_action`    | SAFE / PROVISION | `start` / `stop` / `restart` / `logs` / `inspect` |
| `transfer_files`      | SAFE (download) / varies (upload) | SFTP upload/download of files, folders (recursive), or archives. `extract: true` unpacks an uploaded `.zip`/`.tar.gz`/`.tgz`/`.tar`/`.tar.bz2`/`.tar.xz`/`.gz` on the server; `verifyChecksum: true` does end-to-end sha256 on single files. Uploads to a production-like server hit the write-gate. |

### Mode, consent, audit

| Tool                     | What it does |
| ------------------------ | ------------ |
| `get_current_mode`       | Current mode + permissions + time-remaining |
| `set_mode`               | Change mode. Elevation requires `acknowledgeRisk` + `consentToken` |
| `approve_action`         | Approve a pending high-risk action. Requires `consentToken` |
| `list_pending_approvals` | List queued approval requests |
| `rotate_consent_token`   | Generate a new elevation token. `apply: true` atomically rewrites the MCP client config. Requires the current token. **Read response warnings before restarting the client.** |
| `generate_ssh_key`       | Generate a session SSH keypair with auto-expiry |
| `revoke_ssh_key`         | Revoke a session SSH key |
| `get_audit_log`          | Tail / filter `logs/audit.log` (parses JSON-lines, filters by `since` and `action`) |
| `health_check`           | Liveness + version + current mode |

---

## Authentication options (`add_server`)

Five ways to authenticate, picked by `authType` + which key/password field
you set:

| Option | Schema fields | When to use |
|---|---|---|
| **Password** | `authType:"password"` + `password` (literal **or** `$ENV_VAR`) | When key auth isn't set up. Prefer `$ENV_VAR` so the password isn't on disk in the config. |
| **Copy a key file** | `authType:"key"` + `keyFilePath` | You have a PEM file you want stored alongside the server config (portable bundle) |
| **Paste key inline** | `authType:"key"` + `privateKey` | You have the key text only |
| **Point at existing key** | `authType:"key"` + `externalKeyPath` | You already have `~/.ssh/whatever` — don't copy, just reference. `~` is expanded. |
| **Auto-find your key** | `authType:"key"` + `useExistingKey: true` | Your default `~/.ssh/id_*` is already in `authorized_keys` on the server. Easiest. |

The handler validates **exactly one** key source per call. Combining e.g.
`useExistingKey` and `keyFilePath` is refused with a clear error.

Any key path (`keyFilePath` / `externalKeyPath`) accepts an optional
`keyPassphrase` (literal or `$ENV_VAR`) for encrypted private keys.

### AWS EC2 (the `.pem` case)

You get a `.pem` file, a username (`ubuntu`, `ec2-user`, `admin`, …), and
a public IP/DNS. Two ways:

```jsonc
// Reference the .pem where it sits (recommended — nothing copied)
{
  "id": "my-ec2", "host": "ec2-1-2-3-4.compute.amazonaws.com",
  "username": "ec2-user", "authType": "key",
  "externalKeyPath": "C:\\Users\\you\\Downloads\\my-key.pem",
  "role": "production"
}

// Or copy the .pem into the server's config folder (portable bundle)
{
  "id": "my-ec2", "host": "1.2.3.4", "username": "ubuntu",
  "authType": "key",
  "keyFilePath": "C:\\Users\\you\\Downloads\\my-key.pem",
  "role": "staging"
}
```

Most AWS keys have no passphrase — omit `keyPassphrase`. If yours is
encrypted, add `"keyPassphrase": "$MY_PEM_PASS"` and set that env var.

> **Modern sshd + password auth**: ssh2 needs `tryKeyboard: true` for sshd
> setups that use PAM (Ubuntu 22.04+, Debian 12, Amazon Linux 2023, RHEL 9).
> devops-mcp sets this automatically — passwords work even when the server
> has `PasswordAuthentication no` and only allows `keyboard-interactive`.

---

## Server configuration on disk

Each server lives in its own folder:

```
config/
├── my-vps/
│   ├── server.json     # config (host, user, auth, role, restrictions)
│   ├── key.pem         # optional SSH private key (only if you used keyFilePath / privateKey)
│   └── profile.json    # written by scan_server
└── _example/
    └── server.json     # template
```

`server.json` example:

```json
{
  "name": "Production Web",
  "host": "1.2.3.4",
  "port": 22,
  "username": "ubuntu",
  "authType": "key",
  "keyFile": "production.pem",
  "role": "production",
  "restrictions": {
    "allowedModes": ["SAFE"],
    "blockedCommands": ["rm -rf", "shutdown", "reboot", "dd"],
    "requireApproval": true
  },
  "description": "Main production web server"
}
```

For an `externalKeyPath` workflow (key stays in `~/.ssh/`):

```json
{
  "name": "My VPS",
  "host": "1.2.3.4",
  "port": 22,
  "username": "ubuntu",
  "authType": "key",
  "externalKeyPath": "C:\\Users\\you\\.ssh\\id_ed25519",
  "role": "production"
}
```

For password auth (always prefer `$ENV_VAR`):

```json
{
  "authType": "password",
  "password": "$MY_VPS_PASS"
}
```

`$NAME` is resolved to `process.env.NAME` at connection time. **Don't
commit literal passwords.**

If a `server.json` is missing `role` or has `restrictions: {}`, the MCP
fills in `role: "development"` defaults at load time (and warns in the
logs). This prevents `connect_server` from crashing on hand-written configs.

---

## Environment variables

| Variable                     | Purpose                                                                                              | Default     |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- | ----------- |
| `DEVOPS_MCP_ELEVATION_TOKEN` | Out-of-band consent token. **Set this.** Without it, `set_mode` / `approve_action` / production-write-gate accept the AI's own boolean as consent and the server logs a loud warning. | unset (advisory mode) |
| `DEVOPS_MCP_NO_CONSOLE_LOG`  | Set to `1` to suppress stderr console logs (file logs still written)                                  | unset       |
| `LOG_LEVEL`                  | `debug` / `info` / `warn` / `error`                                                                  | `info`      |
| `LOG_DIR`                    | Where to write `combined.log`, `error.log`, `audit.log`                                              | `./logs`    |
| `NODE_ENV`                   | (Informational; logs go to stderr regardless so MCP stdio isn't corrupted)                           | `development` |

---

## Security model

### What devops-mcp protects against

- **Model running blind on production** — write commands on a server with
  `role: production` or `productionLikely: true` are refused without the
  consent token + explicit ack + (for destructive verbs) `backupVerified`.
- **Self-granted approvals** — the model can't fabricate `consentToken`
  because it never sees `DEVOPS_MCP_ELEVATION_TOKEN`.
- **Argument injection** — every arg to `run_command` is shell-quoted
  before reaching the remote shell. Multi-line scripts inside `sh -c`
  payloads survive intact.
- **Smuggled commands in args** — the validator inspects `command + args`
  together, so `run_command({command:"ls", args:["; rm -rf /"]})` correctly
  escalates to FULL.
- **Over-broad chain refusals** — chains of read-only commands stay SAFE.
  Each fragment is independently validated; only the worst one wins.
- **Prompt injection from scanned content** — banners, container labels,
  log lines are returned with an "untrusted data" marker. The tool response
  tells the model: display, don't execute.
- **Silent port collisions** — `plan_deployment` and `check_port_conflict`
  surface conflicts before deployment.
- **Shell injection in deploy/configure helpers** — every interpolated
  value is shell-quoted; nginx configs are written via heredoc; branch
  names and env-var keys are validated.
- **Production write-gate refusals echo the exact command** — so you can
  read what was about to run, not the AI's paraphrase.

### What devops-mcp does **not** do

- It does not sandbox the *connected* server. Once you're in FULL mode
  with the token, the model can do anything the SSH user can.
- It does not encrypt the consent token at rest in your MCP client config.
- It does not back up your data — `backupVerified` is a human attestation,
  not a check.

See [SECURITY.md](./SECURITY.md) for the full threat model.

---

## Token management

The elevation token is a static string stored in `DEVOPS_MCP_ELEVATION_TOKEN`
in your MCP client config. It does **not** expire.

What expires:
- `FULL` mode session — 30 min default
- `PROVISION` mode session — 1 h default
- Session SSH keys from `generate_ssh_key` — 30 min default

When a mode session times out it drops back to SAFE; the AI re-asks for
the same token to re-elevate.

### Rotating the token

```
You:  Rotate the elevation token and update Claude Desktop's config.
AI:   For verification, paste the current token.
You:  <paste>
AI:   [rotate_consent_token consentToken=<current> apply=true]
      → new token: <new>
      → 🔑 SAVE THIS NOW. Without it you're locked out of every write operation.
      → Fully quit and reopen Claude Desktop to activate it.
```

The MCP writes the new token atomically into your client config (only the
`DEVOPS_MCP_ELEVATION_TOKEN` key — everything else in the file is
preserved). The running MCP process keeps using the **old** token until
you restart the client.

If you lose **both** the old and new tokens between rotation and restart,
hand-edit the client config to set a new one — that's the recovery flow.

---

## Project layout

```
src/
├── index.ts                       # MCP entry point (stdio)
├── types/                         # TypeScript types
├── core/
│   ├── logger.ts                  # JSON-lines structured logger + audit logger
│   ├── mode-manager.ts            # SAFE / PROVISION / FULL state machine
│   ├── command-validator.ts       # Allowlist + quote-aware chain splitter + wrapper-token scan
│   ├── server-config-manager.ts   # config/<id>/server.json + profile.json + auto-heal
│   ├── server-scanner.ts          # SAFE-mode discovery (read-only by design)
│   ├── ssh-key-manager.ts         # Session SSH keys with auto-expiry
│   └── approval-manager.ts        # Approval queue
├── executors/                     # Local / SSH / Docker — all shell-quote args
├── playbooks/                     # Provisioning playbooks (Docker, Nginx, …)
└── tools/
    ├── tool-schemas.ts            # Zod schemas + MCP tool definitions
    └── tool-handlers.ts           # The actual handlers
```

## Development

```bash
npm run dev        # watch mode (tsx)
npm run build      # tsc → dist/
npm test           # vitest
npm run test:run   # vitest run (CI mode)
npm run lint       # eslint src/**/*.ts
```

## Contributing

PRs welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

When adding a new tool that *writes* on the connected server, make sure it
runs through `BaseExecutor.execute()` so the mode validator and the
production write-gate apply. **Do not shell out directly from a handler**,
and if you must interpolate a value into a shell command, use the
`shellQuote` helper in the executor — the historical bugs in this codebase
have all been quoting bugs.

## License

MIT — see [LICENSE](./LICENSE).
