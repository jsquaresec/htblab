"""Shared configuration for the HTB lab bot.

Edit values here, or override DISCORD_WEBHOOK / DISCORD_TOKEN via env vars.
"""
import os

# --- Safety: only these target ranges may ever be queued ---
ALLOWED_PREFIXES = ("10.10.", "10.129.", "10.130.")  # HTB lab ranges
ALLOWED_HOSTNAMES = ()  # e.g. (".htb",) if you use /etc/hosts entries

# --- Storage (shared volume between bot and runner) ---
DB_PATH = os.environ.get("HTB_DB", "/data/jobs.db")
EVIDENCE_DIR = os.environ.get("HTB_EVIDENCE", "/data/evidence")
SCAN_DIR = os.environ.get("HTB_SCANS", "/data/scans")

# --- Discord ---
DISCORD_TOKEN = os.environ.get("DISCORD_TOKEN", "PUT-YOUR-BOT-TOKEN-HERE")
DISCORD_WEBHOOK = os.environ.get("HTB_WEBHOOK", "")  # runner posts progress here

# --- Runner behavior ---
APPROVAL_REQUIRED = True   # human must /approve before any exploit-tier action
APPROVAL_TIMEOUT = 900     # seconds to wait for approval before skipping
ACTION_TIMEOUT = 300       # per-tool timeout
POLL_SECONDS = 5

os.makedirs(EVIDENCE_DIR, exist_ok=True)
os.makedirs(SCAN_DIR, exist_ok=True)
