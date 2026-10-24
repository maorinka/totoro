// Wisp console API client (TypeScript / JavaScript).
// One of io.security's "SDK and API clients". Zero-dependency; uses fetch.
//
//   import { Wisp } from "./wisp";
//   const w = new Wisp("https://console:8080", "operator-token");
//   const risky = (await w.vulns()).filter(v => v.tier === "exploited" || v.tier === "reachable");
//   await w.pushPolicy("web-01", "enforce");   // needs operator role
//   const p1 = await w.incidents({ priority: "P1" });
//   for (const s of await w.suggestions()) await w.decide(s.id, true, "ok");
//   console.log((await w.ask("Which hosts are not enforcing?")).answer);

export type Tier = "exploited" | "vulnerable" | "reachable" | "dormant" | "theoretical";
export interface Host { name: string; group: string; trust: string; cpu_pct: number; alerts: number; execs: number; runtimes: string[]; }
export interface Alert { ts: string; rule: string; severity: string; actor: string; actor_src: string; mitre?: string; title: string; host: string; cmd: string; }
export interface Finding { host: string; ecosystem: string; name: string; version: string; cve: string; severity: string; cvss: number; tier: Tier; note: string; }

export interface Incident { id: string; host: string; group: string; priority: "P1" | "P2" | "P3" | "P4"; score: number; severity: string; status: string;
  first_ts: string; last_ts: string; alert_count: number; rules: string[]; techniques: string[]; actors: string[]; campaign_hosts: string[];
  contained: boolean; summary: string; reasons: string[]; ai: { verdict: string; confidence: string; summary: string; ts: string } | null; }
export interface Suggestion { id: string; ts: string; kind: string; title: string; rationale: string; severity: string; source: "analysis" | "ai";
  status: "proposed" | "applied" | "accepted" | "failed" | "rejected" | "expired"; action: Record<string, unknown>; required_role: string;
  evidence: string[]; decided_by: string; decided_at: string; result: string; }

export class Wisp {
  constructor(private base: string, private token?: string) {
    this.base = base.replace(/\/$/, "");
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const r = await fetch(this.base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}: ${await r.text()}`);
    const text = await r.text();
    return (text ? JSON.parse(text) : null) as T;
  }

  hosts()     { return this.req<Host[]>("GET", "/api/hosts"); }
  alerts()    { return this.req<Alert[]>("GET", "/api/alerts"); }
  inventory() { return this.req<any[]>("GET", "/api/inventory"); }
  vulns()     { return this.req<Finding[]>("GET", "/api/vulns"); }

  incidents(f: { status?: string; priority?: string; host?: string } = {}) {
    const q = new URLSearchParams(Object.entries(f).filter(([, v]) => v) as [string, string][]).toString();
    return this.req<Incident[]>("GET", `/api/incidents${q ? "?" + q : ""}`);
  }
  incident(id: string) { return this.req<Incident & { alerts: Alert[]; suggestions: Suggestion[] }>("GET", `/api/incidents/detail?id=${encodeURIComponent(id)}`); }
  health()     { return this.req<{ status: string; findings: any[] }>("GET", "/api/analysis/health"); }
  ruleReview() { return this.req<any[]>("GET", "/api/analysis/rules"); }
  /** "" = waiting for approval, "all" = everything. */
  suggestions(status = "") { return this.req<Suggestion[]>("GET", `/api/suggestions${status ? "?status=" + status : ""}`); }
  /** Approve (the console carries it out) or reject. Operator; deployer for rollouts. */
  decide(id: string, approve: boolean, note = "") {
    return this.req<Suggestion>("POST", "/api/suggestions/decide", { id, decision: approve ? "approve" : "reject", note });
  }
  triageIncident(id: string, status: "open" | "acknowledged" | "resolved", note = "") {
    return this.req<{ updated: number }>("POST", "/api/incidents/triage", { id, status, note });
  }

  private async ai<T>(kind: string, body: unknown, timeoutMs: number): Promise<T> {
    let job = await this.req<any>("POST", `/api/ai/${kind}`, body);
    const end = Date.now() + timeoutMs;
    while (job.status === "queued" || job.status === "running") {
      if (Date.now() > end) throw new Error(`AI job ${job.id} still ${job.status}`);
      await new Promise((r) => setTimeout(r, 1000));
      job = await this.req<any>("GET", `/api/ai/jobs?id=${encodeURIComponent(job.id)}`);
    }
    if (job.status !== "done") throw new Error(job.error || "AI job failed");
    return job.result as T;
  }
  /** AI assistant (operator; the console needs an API key). */
  aiTriage(incident: string, timeoutMs = 600_000) { return this.ai<any>("triage", { incident }, timeoutMs); }
  aiReviewRule(rule: string, timeoutMs = 600_000) { return this.ai<any>("curate", { rule }, timeoutMs); }
  ask(question: string, timeoutMs = 600_000) { return this.ai<{ answer: string; tool_calls: { name: string; input: unknown }[] }>("ask", { question }, timeoutMs); }

  /** Push 'reload' | 'enforce' | 'monitor' to a host's agent (operator role). */
  pushPolicy(host: string, action: "reload" | "enforce" | "monitor") {
    const q = new URLSearchParams({ host, action }).toString();
    return this.req<{ host: string; action: string; delivered: boolean }>("POST", `/api/policy/push?${q}`);
  }
}
