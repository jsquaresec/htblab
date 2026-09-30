"""Append-only evidence log: every command, its output, and its result."""
import os
import time
from config import EVIDENCE_DIR


class Evidence:
    def __init__(self, job_id):
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        self.path = os.path.join(EVIDENCE_DIR, f"{job_id}.log")

    def _write(self, block):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(block)

    def note(self, msg):
        self._write(f"\n### [{time.strftime('%H:%M:%S')}] {msg}\n")

    def log(self, cmd, rc, stdout, stderr):
        self._write(
            f"\n### [{time.strftime('%H:%M:%S')}] $ {' '.join(cmd)}\n"
            f"[exit code {rc}]\n"
            f"{stdout}\n"
            f"{stderr}\n{'-' * 60}\n"
        )

    def tail(self, n=40):
        if not os.path.exists(self.path):
            return "(no evidence yet)"
        with open(self.path, encoding="utf-8") as f:
            return "".join(f.readlines()[-n:])
