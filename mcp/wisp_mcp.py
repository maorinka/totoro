#!/usr/bin/env python3
"""Wisp MCP server — an MCP-native interface for coding agents.

io.security is "programmatic, agentic and MCP-native ... experiment freely
within limits that are well communicated and enforced in realtime". This
exposes the Wisp fleet's security posture to an AI coding agent over MCP
(stdio, JSON-RPC 2.0), so the agent can see the limits it operates under and
check an action BEFORE taking it:

  tools:
    wisp_fleet        - hosts and their posture
    wisp_alerts       - recent detections
    wisp_vulns        - vulnerability findings (risk-ranked)
    wisp_check_package- is this npm/pip package sanctioned & non-vulnerable?
    wisp_incidents    - correlated, prioritised incidents
    wisp_incident     - one incident with its alerts, AI triage and suggestions
    wisp_fleet_health - fleet health findings
    wisp_suggestions  - remediations waiting for a human to approve

Deliberately read-only: an agent can see what is suggested but cannot approve
anything, so it can never sign off on a change to its own limits.

Config (env): WISP_URL, WISP_TOKEN. Dependency-free (stdlib only), so it runs
under any MCP client. Register it with an agent like any other stdio MCP server:

  { "mcpServers": { "wisp": { "command": "python3",
      "args": ["mcp/wisp_mcp.py"], "env": {"WISP_URL": "...", "WISP_TOKEN":"..."} } } }
"""
import json
import os
import sys
import urllib.request
import urllib.parse
import ssl

BASE = os.environ.get("WISP_URL", "http://127.0.0.1:8080").rstrip("/")
TOKEN = os.environ.get("WISP_TOKEN")
CTX = ssl._create_unverified_context()


def api(path):
    req = urllib.request.Request(BASE + path)
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
        b = r.read()
        return json.loads(b) if b else None


TOOLS = [
    {"name": "wisp_fleet", "description": "List fleet hosts with group, trust tier, CPU, alert and exec counts.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wisp_alerts", "description": "Recent security detections (rule, severity, actor, MITRE, command).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wisp_vulns", "description": "Vulnerability findings across the fleet, risk-ranked (Exploited>Reachable>Dormant).",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wisp_incidents", "description": "Correlated security incidents, highest priority (P1) first, each with a score, the reasons for it and a summary.",
     "inputSchema": {"type": "object", "properties": {"priority": {"type": "string", "enum": ["P1", "P2", "P3", "P4", ""]},
                                                      "host": {"type": "string"}}}},
    {"name": "wisp_incident", "description": "One incident with all of its alerts, the AI triage (if any) and the suggested actions.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
    {"name": "wisp_fleet_health", "description": "Fleet health findings: sensors over CPU budget, silent hosts, version drift, weak identities, unprotected hosts, alert spikes.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wisp_suggestions", "description": "Remediations the console proposes and their status. Approval needs a human operator in the console.",
     "inputSchema": {"type": "object", "properties": {"status": {"type": "string", "enum": ["", "all"]}}}},
    {"name": "wisp_check_package",
     "description": "Before installing a dependency, check whether it is sanctioned by the catalog and free of known vulnerabilities. Returns allow/deny with the reason.",
     "inputSchema": {"type": "object", "properties": {
         "ecosystem": {"type": "string", "enum": ["npm", "pip"]},
         "name": {"type": "string"}, "version": {"type": "string"}},
         "required": ["ecosystem", "name"]}},
]


def check_package(eco, name, version=""):
    # A package is risky if it appears in current vuln findings for that name,
    # or is flagged by any alert (catalog deny / malicious).
    vulns = api("/api/vulns") or []
    for v in vulns:
        if v["ecosystem"] == eco and v["name"].lower() == name.lower():
            return {"allow": False, "reason": f"{v['cve']} ({v['tier']}, cvss {v['cvss']})", "package": name}
    alerts = api("/api/alerts") or []
    for a in alerts:
        if name.lower() in (a.get("cmd", "") + a.get("title", "")).lower() and a.get("rule", "").startswith("CAT"):
            return {"allow": False, "reason": f"catalog policy: {a['title']}", "package": name}
    return {"allow": True, "reason": "no known vulnerability or catalog denial", "package": name}


def call_tool(name, args):
    if name == "wisp_fleet":
        return api("/api/hosts")
    if name == "wisp_alerts":
        return api("/api/alerts")
    if name == "wisp_vulns":
        return api("/api/vulns")
    if name == "wisp_incidents":
        q = urllib.parse.urlencode({k: v for k, v in args.items() if k in ("priority", "host") and v})
        return api("/api/incidents" + (f"?{q}" if q else ""))
    if name == "wisp_incident":
        return api("/api/incidents/detail?" + urllib.parse.urlencode({"id": args["id"]}))
    if name == "wisp_fleet_health":
        return api("/api/analysis/health")
    if name == "wisp_suggestions":
        return api("/api/suggestions" + ("?status=all" if args.get("status") == "all" else ""))
    if name == "wisp_check_package":
        return check_package(args["ecosystem"], args["name"], args.get("version", ""))
    raise ValueError(f"unknown tool {name}")


def reply(id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        m, id = req.get("method"), req.get("id")
        if m == "initialize":
            reply(id, {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                       "serverInfo": {"name": "wisp", "version": "0.1.0"}})
        elif m == "tools/list":
            reply(id, {"tools": TOOLS})
        elif m == "tools/call":
            p = req.get("params", {})
            try:
                out = call_tool(p["name"], p.get("arguments", {}))
                reply(id, {"content": [{"type": "text", "text": json.dumps(out, indent=2)}]})
            except Exception as e:
                reply(id, error={"code": -32000, "message": str(e)})
        elif m == "notifications/initialized":
            pass
        elif id is not None:
            reply(id, error={"code": -32601, "message": f"method not found: {m}"})


if __name__ == "__main__":
    main()
