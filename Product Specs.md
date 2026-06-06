MCP-Based AI Server Automation
Managerial Guidelines & Architecture Document
1. Purpose & Vision

The goal is to build an MCP (Model Context Protocol) system that allows AI tools (Cursor, Windsurf, etc.) to:

Provision servers from near-zero state

Install system packages (Docker, Nginx, language runtimes)

Configure services

Deploy applications

Run operational commands

Return execution results to the AI client

⚠️ Design philosophy:

“AI can do everything a human can — but responsibility and risk ownership stays with the user.”

2. Core Principle: User-Owned Risk

This system must not silently protect users from themselves.

Instead:

Users explicitly choose the risk level

The system enforces transparency, logging, and reversibility

AI actions are auditable

This is critical for:

Enterprise adoption

Legal safety

Open-source credibility

3. System Architecture (High Level)
AI Client (Cursor / Windsurf)
        |
        | MCP Protocol
        |
MCP Control Server
        |
        | Executor Layer (modes)
        |
Target Server (VM / Bare Metal / Cloud)

4. Execution Modes (MANDATORY)

Your MCP must be mode-based.
No single “god mode” by default.

4.1 SAFE MODE (Default)

Purpose: Day-to-day development & CI-like tasks

Capabilities:

Run application commands

Docker exec

Read logs

Run tests

Deploy code

Restrictions:

❌ No root

❌ No system packages

❌ No OS config

Use cases:

Laravel/Django apps

Node apps

CI automation

4.2 PROVISION MODE (High Trust)

Purpose: Initial server setup

Capabilities:

Install packages

Install Docker

Install Nginx

Configure firewall

Configure system services

Rules:

Requires explicit user opt-in

Time-limited

Strong warnings shown to user

Commands logged verbosely

This mode is expected to modify the OS.

4.3 FULL ACCESS MODE (User Responsibility)

Purpose: “Do whatever a senior DevOps engineer can do”

Capabilities:

Full root-level execution

Unrestricted system access

Rules:

Must be explicitly enabled

Requires confirmation flag

Must show irreversible-risk warning

Must log everything

Must support auto-expiry

🔥 This mode exists because users asked for it, not because it’s safe.

5. Permission Model (Formal Spec)

Permissions must be declared, not inferred.

Example Permission Declaration
{
  "mode": "provision",
  "permissions": {
    "os": true,
    "docker": true,
    "nginx": true,
    "firewall": false,
    "disk": false
  },
  "expires_in": "60m"
}


Rules:

Permissions are machine-readable

AI decisions are constrained by this object

Developers must enforce it at executor level

6. Executor Design Rules
6.1 Never expose raw shell directly

Commands must pass through:

Validator

Logger

Timeout controller

6.2 Always tag executions

Every command execution must record:

Timestamp

Mode

User

Command

Result

Exit code

7. Root Access & Expiry Policy

If root is enabled:

Mandatory rules:

Time-limited keys (TTL)

Auto-revoke after expiry

No persistent credentials

One active root session max

Example Policy

Root access valid for 30–60 minutes

Auto-disabled on disconnect

Explicit re-approval required

8. AI Behavior Constraints

AI must:

Explain what it is about to do

Prefer idempotent actions

Avoid destructive defaults

Ask for confirmation when unsure (configurable)

Example:

“I will install Docker, enable it at boot, and open port 80. Proceed?”

9. Provisioning Strategy (Recommended)
Preferred:

Idempotent scripts

Playbook-style execution

Step-by-step phases

Examples:

install_docker

install_nginx

configure_reverse_proxy

deploy_container

Avoid:

One-liner bash pipelines

Unreviewable scripts

10. Human Approval Checkpoints (Optional but Recommended)

For high-risk actions:

Firewall changes

Disk operations

System upgrades

Require:

Explicit approval flag

Or human confirmation prompt

11. Logging & Audit (Non-negotiable)

Logs must be:

Immutable

Timestamped

Mode-tagged

Exportable

This protects:

Users

Your company

Open-source contributors

12. Open-Source Readiness Guidelines

If open-sourcing:

You MUST:

Document risks clearly

Default to safe mode

Make dangerous modes opt-in

Avoid marketing it as “safe by default for root”

Transparency > false safety.

13. What This System Is NOT

❌ Not a fully autonomous AI sysadmin
❌ Not a silent root bot
❌ Not a replacement for responsibility

It is:
✔ A powerful execution assistant
✔ A controlled automation layer
✔ A user-owned risk system

14. Manager Checklist ✅

Before approving development:

 Modes implemented

 Permission spec defined

 Root expiry enforced

 Logging implemented

 Warnings visible to users

 Clear documentation

15. Final Manager Statement (You Can Reuse)

“This MCP allows AI to operate servers with human-level capability.
Risk level is chosen explicitly by the user.
All actions are logged, auditable, and reversible where possible.”