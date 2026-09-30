"""HTB job runner — run this inside the Kali container.

Loop: claim queued job -> enumerate -> plan approved actions -> report.
Posts progress to Discord via webhook; logs everything as evidence.
"""
import json, subprocess, time, urllib.request
from actions import ACTIONS, plan, parse_open_ports, detect_flags
from config import (ACTION_TIMEOUT, APPROVAL_REQUIRED, APPROVAL_TIMEOUT,
                    DISCORD_WEBHOOK, POLL_SECONDS)
from evidence import Evidence
import jobs


def webhook(content=None, embed=None):
    if not DISCORD_WEBHOOK:
        return
    payload = {"content": content, "embeds": [embed] if embed else []}
    req = urllib.request.Request(
        DISCORD_WEBHOOK, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "J2Sec-HTB-Runner/1.0"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[webhook error] {e}")


def embed(title, body, color=0x5865F2):
    return {"title": title, "description": f"```\n{body[:3500]}\n```",
            "color": color}


def run_cmd(cmd, ev, timeout=ACTION_TIMEOUT):
    ev.note(f"running: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ev.log(cmd, p.returncode, p.stdout, p.stderr)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        ev.note(f"TIMEOUT after {timeout}s: {' '.join(cmd)}")
        return -1, ""


def cancelled(job_id):
    j = jobs.get(job_id)
    return not j or j["status"] == "cancelled"


def request_approval(job, action_id):
    jobs.update(job["id"], status="awaiting_approval",
                action=json.dumps({"id": action_id}))
    webhook(f"⏸️ **Approval needed** — job `{job['id']}` target `{job['ip']}`\n"
            f"Action: **{ACTIONS[action_id]['desc']}**\n"
            f"Approve with `/approve {job['id']}` or deny with `/deny {job['id']}`",
            embed=embed("Pending action", ACTIONS[action_id]["build"](
                job["ip"], build_ctx(job, ""))))
    deadline = time.time() + APPROVAL_TIMEOUT
    while time.time() < deadline:
        time.sleep(POLL_SECONDS)
        j = jobs.get(job["id"])
        if j["status"] == "approved":
            jobs.update(job["id"], status="running", action="")
            return True
        if j["status"] in ("denied", "cancelled"):
            jobs.update(job["id"], status="running", action="")
            return False
    jobs.update(job["id"], status="running", action="")
    return False


def build_ctx(job, ports):
    ctx = {"job_id": job["id"], "ports": ports}
    # creds supplied as notes in "user:pass" form
    if ":" in (job["notes"] or ""):
        u, p = job["notes"].split(":", 1)
        ctx.update(username=u.strip(), password=p.strip())
    return ctx


def has_creds(job):
    return ":" in (job["notes"] or "")


def process(job):
    jid, ip = job["id"], job["ip"]
    ev = Evidence(jid)
    jobs.update(jid, status="running")
    webhook(f"▶️ Job `{jid}` started on `{ip}` ({job['platform']})")

    # 0. host reachable?
    rc, out = run_cmd(["nmap", "-sn", "-Pn", ip], ev, timeout=60)
    if rc != 0 or "Host seems down" in out:
        jobs.update(jid, status="done: host unreachable")
        webhook(f"❌ Job `{jid}`: host unreachable")
        return

    # 1. full port scan
    rc, out = run_cmd(ACTIONS["nmap_full"]["build"](ip, build_ctx(job, "")), ev)
    if cancelled(jid):
        return
    ports = parse_open_ports(out)
    if not ports:
        jobs.update(jid, status="done: no open ports")
        webhook(f"🏁 Job `{jid}`: no open ports found.")
        return
    webhook(f"🔍 Job `{jid}`: ports found — {', '.join(map(str, ports))}",
            embed=embed("Open ports", ", ".join(map(str, ports)), 0x57F287))

    # 2. planned actions
    steps = plan(ports, has_creds(job))
    flags = []
    for action_id in steps:
        if cancelled(jid):
            return
        a = ACTIONS[action_id]
        if a["tier"] == "exploit" and APPROVAL_REQUIRED:
            if not request_approval(job, action_id):
                ev.note(f"action skipped (denied/timeout): {action_id}")
                continue
        ctx = build_ctx(job, ",".join(map(str, ports)))
        rc, out = run_cmd(a["build"](ip, ctx), ev)
        result_icon = "✅" if rc == 0 else "⚠️"
        summary = out.strip() or "(no stdout/stderr returned)"
        webhook(
            f"{result_icon} Job `{jid}`: {a['desc']} finished (exit {rc})",
            embed=embed(f"{a['desc']} // exit {rc}", summary,
                        0x57F287 if rc == 0 else 0xFEE75C),
        )
        if a.get("flag_check"):
            flags += [f for f in detect_flags(out) if f not in flags]
            if flags:
                jobs.update(jid, flags=json.dumps(flags))

    status = f"done: {len(flags)} flag(s) found" if flags else "done: no flags"
    jobs.update(jid, status=status)
    webhook(f"🏁 Job `{jid}` {status}" +
            (f"\nFlags: `{', '.join(flags)}`" if flags else ""),
            embed=embed("Final evidence tail", ev.tail(20),
                        0x57F287 if flags else 0xED4245))


def main():
    jobs.init()
    print("[runner] waiting for jobs...")
    while True:
        try:
            job = jobs.next_queued()
            if job:
                print(f"[runner] claiming {job['id']}")
                try:
                    process(job)
                except Exception as e:
                    jobs.update(job["id"], status=f"error: {e}")
                    webhook(f"💥 Job `{job['id']}` crashed: {e}")
            else:
                time.sleep(POLL_SECONDS)
        except Exception as e:
            print(f"[runner] loop error: {e}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
