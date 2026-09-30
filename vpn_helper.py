#!/usr/bin/env python3
"""Minimal host-side control socket for the HTB OpenVPN systemd unit."""

import json
import os
import socket
import subprocess

SOCKET_PATH = "/run/htblab/vpn.sock"
UNIT = "openvpn-client@htb.service"
ACTIONS = {"start", "stop", "restart", "status"}


def service_state():
    proc = subprocess.run(
        ["systemctl", "is-active", UNIT],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return (proc.stdout.strip() or "unknown").lower()


def handle(payload):
    action = payload.get("action")
    if action not in ACTIONS:
        return {"ok": False, "state": service_state(), "message": "Unsupported action."}

    if action != "status":
        try:
            proc = subprocess.run(
                ["systemctl", action, UNIT],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "state": service_state(), "message": "Service action timed out."}
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "systemctl failed").strip()
            return {"ok": False, "state": service_state(), "message": message}

    state = service_state()
    if action == "stop":
        ok = state in {"inactive", "failed"}
    else:
        ok = state == "active"
    return {"ok": ok, "state": state}


def main():
    os.makedirs(os.path.dirname(SOCKET_PATH), mode=0o755, exist_ok=True)
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o660)
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    raw = b""
                    while b"\n" not in raw and len(raw) < 4096:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        raw += chunk
                    payload = json.loads(raw.decode().strip())
                    result = handle(payload)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    result = {"ok": False, "state": service_state(), "message": f"Invalid request: {exc}"}
                conn.sendall((json.dumps(result) + "\n").encode())


if __name__ == "__main__":
    main()
