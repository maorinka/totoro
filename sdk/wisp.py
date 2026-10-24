"""Wisp console API client (Python 3).

One of io.security's "SDK and API clients". Thin, dependency-free wrapper over
the console REST API, with the RBAC bearer token.

    from wisp import Wisp
    w = Wisp("https://console:8080", token="operator-token")
    for v in w.vulns():
        if v["tier"] in ("exploited", "reachable"):
            print(v["name"], v["cve"], v["tier"])
    w.push_policy("web-01", "enforce")     # needs operator role

    for inc in w.incidents(priority="P1"):
        print(inc["id"], inc["host"], inc["summary"])
    for s in w.suggestions():                # waiting for approval
        print(s["id"], s["title"])
    w.decide(s["id"], approve=True, note="ok") # operator (deployer for rollouts)
    print(w.ask("Which hosts are not enforcing?")["answer"])  # needs the AI assistant
"""
from __future__ import annotations
import json
import ssl
import time
import urllib.request
import urllib.parse


class WispError(RuntimeError):
    pass


class Wisp:
    def __init__(self, base_url: str, token: str | None = None, verify: bool = True):
        self.base = base_url.rstrip("/")
        self.token = token
        self._ctx = None if verify else ssl._create_unverified_context()

    def _get(self, path: str, **query):
        q = urllib.parse.urlencode({k: v for k, v in query.items() if v not in (None, "")})
        return self._req("GET", path + (f"?{q}" if q else ""))

    def _req(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=15) as r:
                body = r.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            raise WispError(f"{e.code} {e.reason}: {e.read().decode(errors='replace')}")

    # --- read endpoints (viewer+) ---
    def hosts(self) -> list:
        """Fleet: every host with its group, trust tier, CPU, alerts, execs."""
        return self._get("/api/hosts") or []

    def alerts(self) -> list:
        """Recent detections, newest first (rule, severity, actor, MITRE, cmd)."""
        return self._get("/api/alerts") or []

    def inventory(self) -> list:
        """Discovered packages / extensions / tools across the fleet."""
        return self._get("/api/inventory") or []

    def vulns(self) -> list:
        """Vulnerability findings, risk-ranked (Exploited>Reachable>...)."""
        return self._get("/api/vulns") or []

    # --- analysis (viewer+) ---
    def incidents(self, status: str = "", priority: str = "", host: str = "") -> list:
        """Correlated incidents, highest priority first. status '' = not resolved."""
        return self._get("/api/incidents", status=status, priority=priority, host=host) or []

    def incident(self, incident_id: str) -> dict:
        """One incident with its alerts, AI triage and suggestions."""
        return self._get("/api/incidents/detail", id=incident_id)

    def health(self) -> dict:
        """Fleet health findings."""
        return self._get("/api/analysis/health")

    def rule_review(self) -> list:
        """Per-rule volume, triage outcomes and assessment (noisy / ready_to_enforce)."""
        return self._get("/api/analysis/rules") or []

    def suggestions(self, status: str = "") -> list:
        """Suggestions; '' = waiting for approval, 'all' = everything."""
        return self._get("/api/suggestions", status=status) or []

    # --- decisions (operator+; deployer for rollout suggestions) ---
    def decide(self, suggestion_id: str, approve: bool, note: str = "") -> dict:
        """Approve (the console carries it out) or reject a suggestion."""
        return self._req("POST", "/api/suggestions/decide",
                         {"id": suggestion_id, "decision": "approve" if approve else "reject", "note": note})

    def triage_incident(self, incident_id: str, status: str, note: str = "") -> dict:
        """Set every alert in an incident to open | acknowledged | resolved."""
        return self._req("POST", "/api/incidents/triage", {"id": incident_id, "status": status, "note": note})

    # --- AI assistant (operator+; the console must have an API key) ---
    def _ai(self, kind: str, body: dict, timeout: float) -> dict:
        job = self._req("POST", f"/api/ai/{kind}", body)
        deadline = time.time() + timeout
        while job["status"] in ("queued", "running"):
            if time.time() > deadline:
                raise WispError(f"AI job {job['id']} still {job['status']} after {timeout}s")
            time.sleep(1)
            job = self._get("/api/ai/jobs", id=job["id"])
        if job["status"] != "done":
            raise WispError(job.get("error") or "AI job failed")
        return job["result"]

    def ai_triage(self, incident_id: str, timeout: float = 600) -> dict:
        """Verdict, reasoning and recommended actions (added to suggestions)."""
        return self._ai("triage", {"incident": incident_id}, timeout)

    def ai_review_rule(self, rule: str, timeout: float = 600) -> dict:
        """Assessment and proposed rules.conf lines for one rule."""
        return self._ai("curate", {"rule": rule}, timeout)

    def ask(self, question: str, timeout: float = 600) -> dict:
        """Ask about the fleet; returns {answer, tool_calls}."""
        return self._ai("ask", {"question": question}, timeout)

    # --- control (operator+) ---
    def push_policy(self, host: str, action: str) -> dict:
        """Push 'reload' | 'enforce' | 'monitor' to a host's agent."""
        if action not in ("reload", "enforce", "monitor"):
            raise ValueError("action must be reload|enforce|monitor")
        q = urllib.parse.urlencode({"host": host, "action": action})
        return self._req("POST", f"/api/policy/push?{q}")


if __name__ == "__main__":
    import os, sys
    w = Wisp(os.environ.get("WISP_URL", "http://127.0.0.1:8080"),
             token=os.environ.get("WISP_TOKEN"), verify=False)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "hosts"
    if cmd == "push":
        print(w.push_policy(sys.argv[2], sys.argv[3]))
    elif cmd == "ask":
        print(w.ask(" ".join(sys.argv[2:]))["answer"])
    else:
        print(json.dumps(getattr(w, cmd)(), indent=2))
