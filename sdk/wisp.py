"""Wisp console API client (Python 3).

One of io.security's "SDK and API clients". Thin, dependency-free wrapper over
the console REST API, with the RBAC bearer token.

TLS: certificates are always verified. For a console with a private CA pass
cafile="/path/ca.pem" (the CLI reads WISP_CA or --ca). Turning verification
off needs the explicit insecure_skip_tls_verify=True and is for throwaway dev
setups only: anyone on the network path can then steal the bearer token.

    from wisp import Wisp
    w = Wisp("https://console:8080", token="operator-token", cafile="ca.pem")
    for v in w.vulns():
        if v["tier"] in ("exploited", "reachable"):
            print(v["name"], v["cve"], v["tier"])
    w.push_policy("web-01", "enforce")     # needs operator role

    for inc in w.incidents(priority="P1"):
        print(inc["id"], inc["host"], inc["summary"])

    # SECURITY: never approve suggestions in bulk. AI-sourced suggestions
    # (s["source"] == "ai") are derived from endpoint telemetry, which an
    # attacker controls (prompt injection via command lines, file names...),
    # so a human must review each one in the console. The console refuses
    # AI-sourced approvals without the deployer role. Rollouts change fleet
    # policy and also belong to a human. Below: only analysis-sourced,
    # non-rollout suggestions, and each one is shown and confirmed by a person.
    for s in w.suggestions():                # waiting for approval
        if s["source"] == "ai" or s["action"].get("type") == "rollout":
            print("review in the console:", s["id"], s["title"])
            continue
        print(s["id"], s["title"], s["rationale"], s["evidence"])
        if input(f"approve {s['id']}? [y/N] ").strip().lower() == "y":
            w.decide(s["id"], approve=True, note="reviewed by <name>")   # operator
    print(w.ask("Which hosts are not enforcing?")["answer"])  # needs the AI assistant

Errors: every failure (HTTP status, connection, DNS, TLS, timeout) raises
WispError; the original exception is chained as __cause__.
"""
from __future__ import annotations
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class WispError(RuntimeError):
    pass


def _is_loopback(host: str) -> bool:
    if host in ("localhost", "localhost.") or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def tls_context(cafile: str | None = None, insecure_skip_tls_verify: bool = False) -> ssl.SSLContext:
    """A verifying TLS context (system trust store, plus `cafile` if given).

    insecure_skip_tls_verify=True disables certificate and hostname checks.
    Dev only: the bearer token goes to whoever answers.
    """
    if insecure_skip_tls_verify:
        print("wisp: WARNING: TLS certificate verification is DISABLED; the bearer "
              "token can be stolen by anyone on the network path", file=sys.stderr)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context(cafile=cafile or None)


class Wisp:
    def __init__(self, base_url: str, token: str | None = None, *, cafile: str | None = None,
                 context: ssl.SSLContext | None = None, insecure_skip_tls_verify: bool = False,
                 allow_plaintext_token: bool = False, timeout: float = 15, verify: bool = True):
        """base_url: https://console:8080. TLS is always verified unless
        insecure_skip_tls_verify=True. cafile: PEM bundle for a private CA.
        context: a fully custom ssl.SSLContext (overrides cafile).
        A token is never sent over plain http:// to a non-loopback host unless
        allow_plaintext_token=True. verify=False is a deprecated spelling of
        insecure_skip_tls_verify=True."""
        if not verify:
            import warnings
            warnings.warn("Wisp(verify=False) is deprecated; use insecure_skip_tls_verify=True "
                          "(dev only) or cafile= for a private CA", DeprecationWarning, stacklevel=2)
            insecure_skip_tls_verify = True
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        u = urllib.parse.urlsplit(self.base)
        if u.scheme not in ("http", "https"):
            raise ValueError("base_url must be http:// or https://")
        if token and u.scheme == "http" and not _is_loopback(u.hostname or "") and not allow_plaintext_token:
            raise WispError(f"refusing to send the bearer token over plain http to {u.hostname}; "
                            "use https:// (or allow_plaintext_token=True)")
        self._ctx = context or tls_context(cafile, insecure_skip_tls_verify)

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
            with urllib.request.urlopen(req, context=self._ctx, timeout=self.timeout) as r:
                raw = r.read()
            return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            try:
                detail = e.read().decode(errors="replace")
            except Exception:
                detail = ""
            raise WispError(f"{e.code} {e.reason}: {detail}") from e
        except urllib.error.URLError as e:
            raise WispError(f"{method} {path}: {e.reason}") from e
        except (TimeoutError, socket.timeout, ssl.SSLError, OSError) as e:
            raise WispError(f"{method} {path}: {e}") from e
        except ValueError as e:  # JSON decode
            raise WispError(f"{method} {path}: invalid JSON response: {e}") from e

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
        """Approve (the console carries it out) or reject a suggestion.

        Never call this in a loop over suggestions(). A human must review every
        suggestion before approval, above all AI-sourced ones (source == "ai"):
        they are derived from attacker-controllable endpoint telemetry and may
        be the product of prompt injection. The console refuses AI-sourced
        approvals without the deployer role."""
        return self._req("POST", "/api/suggestions/decide",
                         {"id": suggestion_id, "decision": "approve" if approve else "reject", "note": note})

    def triage_incident(self, incident_id: str, status: str, note: str = "") -> dict:
        """Set every alert in an incident to open | acknowledged | resolved."""
        return self._req("POST", "/api/incidents/triage", {"id": incident_id, "status": status, "note": note})

    # --- AI assistant (operator+; the console must have an API key) ---
    def _ai(self, kind: str, body: dict, timeout: float) -> dict:
        job = self._req("POST", f"/api/ai/{kind}", body)
        deadline = time.time() + timeout
        failures = 0
        while job["status"] in ("queued", "running"):
            if time.time() > deadline:
                raise WispError(f"AI job {job['id']} still {job['status']} after {timeout}s")
            time.sleep(1)
            try:
                job = self._get("/api/ai/jobs", id=job["id"])
                failures = 0
            except WispError as e:
                # Transient (console restart, network blip): keep polling, and
                # always report the job id so the caller can resume.
                failures += 1
                cause = e.__cause__
                transient = not isinstance(cause, urllib.error.HTTPError) or cause.code >= 500
                if not transient or failures >= 5:
                    raise WispError(f"AI job {job['id']}: polling failed: {e}") from e
        if job["status"] != "done":
            raise WispError(f"AI job {job['id']}: " + (job.get("error") or "AI job failed"))
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


def _main(argv: list[str]) -> int:
    import argparse
    import os
    ap = argparse.ArgumentParser(prog="wisp.py", description="Wisp console CLI (env: WISP_URL, WISP_TOKEN, WISP_CA)")
    ap.add_argument("--ca", default=os.environ.get("WISP_CA"), help="PEM CA bundle for the console certificate")
    ap.add_argument("--insecure-skip-tls-verify", action="store_true",
                    help="DANGEROUS, dev only: accept any TLS certificate (token can be stolen)")
    ap.add_argument("cmd", nargs="?", default="hosts")
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    try:
        w = Wisp(os.environ.get("WISP_URL", "http://127.0.0.1:8080"), token=os.environ.get("WISP_TOKEN"),
                 cafile=a.ca, insecure_skip_tls_verify=a.insecure_skip_tls_verify)
        if a.cmd == "push":
            if len(a.args) != 2:
                ap.error("usage: push <host> reload|enforce|monitor")
            print(w.push_policy(a.args[0], a.args[1]))
        elif a.cmd == "ask":
            print(w.ask(" ".join(a.args))["answer"])
        elif a.cmd in ("hosts", "alerts", "inventory", "vulns", "incidents", "health", "rule_review", "suggestions"):
            print(json.dumps(getattr(w, a.cmd)(), indent=2))
        else:
            ap.error(f"unknown command {a.cmd}")
    except WispError as e:
        print(f"wisp: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
