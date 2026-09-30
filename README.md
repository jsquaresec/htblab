# HTB Lab Discord Bot

A Discord bot + isolated Kali runner that automates enumeration against
**authorized Hack The Box lab targets** and reports `user.txt` / `root.txt`
flags — with an evidence log, target allowlist, job queue, timeouts,
cancellation, and human approval before any exploit-tier action.

## Architecture

```
You  →  Discord bot (/htb start)  →  SQLite job queue  →  Kali runner (container)
                                                          │ nmap → plan approved
                                                          │ actions → flag detect
You  ←  progress embeds (webhook)  ←  evidence log ←──────┘
```

## Setup

1. **Discord app:** [Developer Portal](https://discord.com/developers) → New
   Application → Bot → copy the **token**. Invite the bot to your server with
   the `applications.commands` scope (OAuth2 → URL Generator).

2. **Progress webhook:** Server Settings → Integrations → Webhooks → New →
   copy the webhook URL.

3. **Configure:**
   ```bash
   export DISCORD_TOKEN="..."
   export HTB_WEBHOOK="https://discord.com/api/webhooks/..."
   ```
   Optionally edit `ALLOWED_PREFIXES` in `config.py`.

4. **Run:**
   ```bash
   docker compose up --build
   ```

5. **VPN:** connect to HTB on the host (`tun0`). The runner uses
   `network_mode: host` so it reaches lab machines through your tunnel.

## Usage

```
/htb ip:10.129.1.5 platform:linux notes:user:password
/status job_id:ab12cd34
/results job_id:ab12cd34
/cancel job_id:ab12cd34
/approve job_id:ab12cd34      # when the runner asks before exploit-tier steps
/jobs
```

## Safety properties

- Targets outside `ALLOWED_PREFIXES` are refused at queue time.
- One job at a time; every tool has a timeout; `/cancel` stops the run.
- The orchestration layer can only pick actions from the fixed `ACTIONS`
  menu — no free-form shell.
- Flags are reported only when matched against output of flag-retrieval
  actions; nothing is invented.
- Every command + output is appended to `/data/evidence/<job_id>.log`.

## Extending

Add new approved actions in `actions.py` (set `tier` and `flag_check`
appropriately), and teach `plan()` when to choose them. Swap the rule-based
`plan()` for an LLM that selects from the same fixed menu if you want
adaptive behavior — keep the approval gate.
