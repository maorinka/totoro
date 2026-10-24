#!/usr/bin/env python3
"""A local stand-in for the Claude Messages API, for testing the console's AI
assistant without an API key or network access.

    python3 bench/mock_claude_api.py --port 9443 --cert C.crt --key C.key [--log requests.jsonl]

It serves POST /v1/messages over TLS and checks each request the way the real
API would (headers, model, structured-output schema rules, strict tools,
tool_use / tool_result pairing, the fallback beta). A request that breaks a
rule gets a 400 invalid_request_error, so the console's error path is
exercised too. Replies are deterministic:

  - triage (schema with "recommended_actions"): a verdict plus one push, one
    triage and one manual action, and one out-of-scope push the console must
    drop
  - curate (schema with "proposals"): one valid rule line and one malformed one
  - ask (tools present): calls list_incidents, then answers citing the result

Special questions for error-path tests: "REFUSE" returns stop_reason refusal;
"RATE" returns 429 once.
"""
import argparse, json, ssl, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=9443)
ap.add_argument("--cert", required=True)
ap.add_argument("--key", required=True)
ap.add_argument("--log", default="")
args = ap.parse_args()

lock = threading.Lock()
rate_once = {"done": False}


def problems(req, headers):
    out = []
    if not headers.get("x-api-key"):
        out.append("missing x-api-key")
    if headers.get("anthropic-version") != "2026-10-21":
        out.append("anthropic-version must be 2026-10-21")
    if not isinstance(req.get("model"), str) or not req["model"].startswith("claude-"):
        out.append("model")
    if not isinstance(req.get("max_tokens"), int) or req["max_tokens"] <= 0:
        out.append("max_tokens")
    for k in ("temperature", "top_p", "top_k", "budget_tokens"):
        if k in req:
            out.append(f"{k} is not accepted")
    th = req.get("thinking")
    if th is not None and th.get("type") != "adaptive":
        out.append("thinking must be adaptive or omitted")
    if "fallbacks" in req:
        if req["fallbacks"] != "default" or "server-side-fallback-2026-07-01" not in headers.get("anthropic-beta", ""):
            out.append("fallbacks needs the server-side-fallback-2026-07-01 beta")
    oc = req.get("output_config", {})
    if oc.get("effort") not in (None, "low", "medium", "high", "xhigh", "max"):
        out.append("output_config.effort")
    fmt = oc.get("format")
    if fmt is not None:
        if fmt.get("type") != "json_schema":
            out.append("format.type must be json_schema")
        check_schema(fmt.get("schema"), "schema", out)
    for t in req.get("tools", []):
        if t.get("strict"):
            check_schema(t.get("input_schema"), f"tools.{t.get('name')}", out)
    msgs = req.get("messages", [])
    if not msgs or msgs[0].get("role") != "user":
        out.append("messages must start with a user turn")
    for a, b in zip(msgs, msgs[1:]):
        if a.get("role") == b.get("role"):
            out.append("roles must alternate")
        if a.get("role") == "assistant" and isinstance(a.get("content"), list):
            ids = {c["id"] for c in a["content"] if c.get("type") == "tool_use"}
            got = {c.get("tool_use_id") for c in (b.get("content") or []) if isinstance(c, dict) and c.get("type") == "tool_result"}
            if ids != got:
                out.append("every tool_use needs its tool_result in the next user message")
    if msgs and msgs[-1].get("role") == "assistant":
        out.append("assistant prefill is not supported")
    return out


def check_schema(s, path, out):
    if not isinstance(s, dict):
        out.append(f"{path}: not an object")
        return
    t = s.get("type")
    if t == "object":
        if s.get("additionalProperties") is not False:
            out.append(f"{path}: additionalProperties must be false")
        props = s.get("properties", {})
        if set(s.get("required", [])) - set(props):
            out.append(f"{path}: required names an unknown property")
        for k, v in props.items():
            check_schema(v, f"{path}.{k}", out)
    elif t == "array":
        check_schema(s.get("items"), f"{path}[]", out)
    for bad in ("minimum", "maximum", "minLength", "maxLength", "pattern"):
        if bad in s:
            out.append(f"{path}: {bad} is not supported")


def text_of(req):
    m = req["messages"][0]["content"]
    return m if isinstance(m, str) else json.dumps(m)


def fleet_data(text):
    s = text.find("<fleet_data>")
    e = text.find("</fleet_data>")
    return json.loads(text[s + len("<fleet_data>"):e]) if s >= 0 and e > s else {}


def message(content, stop="end_turn", model="claude-opus-5-5"):
    return {"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": content,
            "stop_reason": stop, "stop_details": None,
            "usage": {"input_tokens": 1200, "output_tokens": 300, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}}


def reply(req):
    schema = (req.get("output_config", {}).get("format") or {}).get("schema", {})
    props = schema.get("properties", {})
    thinking = {"type": "thinking", "thinking": "", "signature": "mock-signature"}
    if "recommended_actions" in props:
        inc = fleet_data(text_of(req))
        host = inc.get("host", "")
        result = {
            "verdict": "malicious", "confidence": "high",
            "summary": f"Credential theft followed by a reverse shell on {host}. Contain it now.",
            "reasoning": [f"{a.get('rule')}: {a.get('cmd')}" for a in inc.get("alerts", [])][:4],
            "recommended_actions": [
                {"type": "push", "title": f"Enforce on {host}", "rationale": "stop the next stage", "host": host, "group": "",
                 "control": "enforce", "percent": 0, "triage_status": "", "instructions": ""},
                {"type": "triage", "title": "Acknowledge the alerts", "rationale": "confirmed malicious", "host": "", "group": "",
                 "control": "", "percent": 0, "triage_status": "acknowledged", "instructions": ""},
                {"type": "manual", "title": "Rotate the SSH keys", "rationale": "the private key was read", "host": "", "group": "",
                 "control": "", "percent": 0, "triage_status": "", "instructions": f"Rotate every SSH key on {host} and revoke it in authorized_keys fleet-wide."},
                {"type": "push", "title": "Enforce on an unrelated host", "rationale": "out of scope on purpose", "host": "web-99",
                 "group": "", "control": "enforce", "percent": 0, "triage_status": "", "instructions": ""},
            ]}
        return message([thinking, {"type": "text", "text": json.dumps(result)}], model=req["model"])
    if "proposals" in props:
        d = fleet_data(text_of(req))
        rule = d.get("rule", "RULE-1")
        prog = (d.get("top_programs") or [{"program": "git"}])[0]["program"]
        result = {"verdict": "tune", "assessment": f"{rule} mostly fires on {prog}, which was closed as benign.",
                  "proposals": [
                      {"change": "narrow", "rule_line": f'{rule} high alert T1552.001 "Read of SSH private key" cmd*=/.ssh/id_ !comm=ssh,ssh-add,sshd,git,{prog}',
                       "rationale": f"exclude {prog}"},
                      {"change": "new_rule", "rule_line": f"{rule}-X bogus", "rationale": "malformed on purpose"}]}
        return message([thinking, {"type": "text", "text": json.dumps(result)}], model=req["model"])
    if req.get("tools"):
        q = text_of(req)
        if "REFUSE" in q:
            return message([], stop="refusal") | {"stop_details": {"type": "refusal", "category": "cyber", "explanation": "mock"}}
        msgs = req["messages"]
        if len(msgs) == 1:
            return message([thinking, {"type": "text", "text": "Let me look at the incidents."},
                            {"type": "tool_use", "id": "toolu_1", "name": "list_incidents",
                             "input": {"status": "open", "priority": "", "host": ""}}], stop="tool_use", model=req["model"])
        res = msgs[-1]["content"][0]["content"]
        data = fleet_data(res if isinstance(res, str) else json.dumps(res))
        items = data if isinstance(data, list) else data.get("items", [])
        top = items[0] if items else {}
        return message([{"type": "text", "text": f"There are {len(items)} open incidents. The most urgent is {top.get('id')} on {top.get('host')} ({top.get('priority')})."}], model=req["model"])
    return message([{"type": "text", "text": "ok"}], model=req["model"])


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, obj, extra=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        try:
            req = json.loads(body)
        except ValueError:
            return self.send(400, {"type": "error", "error": {"type": "invalid_request_error", "message": "bad json"}})
        if args.log:
            with lock, open(args.log, "a") as f:
                f.write(json.dumps({"path": self.path, "headers": {k: v for k, v in hdrs.items() if k != "x-api-key"},
                                    "key_present": bool(hdrs.get("x-api-key")), "body": req}) + "\n")
        if self.path != "/v1/messages":
            return self.send(404, {"type": "error", "error": {"type": "not_found_error", "message": self.path}})
        if hdrs.get("x-api-key") == "bad":
            return self.send(401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})
        p = problems(req, hdrs)
        if p:
            return self.send(400, {"type": "error", "error": {"type": "invalid_request_error", "message": "; ".join(p)}})
        if "RATE" in text_of(req):
            with lock:
                first = not rate_once["done"]
                rate_once["done"] = True
            if first:
                return self.send(429, {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}, {"retry-after": "1"})
        self.send(200, reply(req))


srv = ThreadingHTTPServer(("127.0.0.1", args.port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(args.cert, args.key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(f"mock Claude API on https://127.0.0.1:{args.port}", flush=True)
srv.serve_forever()
