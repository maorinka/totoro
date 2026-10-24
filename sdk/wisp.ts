// Wisp console API client (TypeScript / JavaScript).
// One of io.security's "SDK and API clients". Zero-dependency; uses fetch.
//
// TLS: fetch always verifies certificates. For a console with a private CA,
// run Node with NODE_EXTRA_CA_CERTS=/path/ca.pem, or pass a `fetch` bound to
// your own undici Agent/dispatcher with that CA. Never set
// NODE_TLS_REJECT_UNAUTHORIZED=0: anyone on the path can then steal the token.
// A token is never sent over plain http:// to a non-loopback host unless
// { allowPlaintextToken: true } is passed.
//
//   import { Wisp } from "./wisp";
//   const w = new Wisp("https://console:8080", "operator-token");
//   const risky = (await w.vulns()).filter(v => v.tier === "exploited" || v.tier === "reachable");
//   await w.pushPolicy("web-01", "enforce");   // needs operator role
//   const p1 = await w.incidents({ priority: "P1" });
//
//   // SECURITY: never approve suggestions in bulk. AI-sourced suggestions
//   // (source === "ai") are derived from endpoint telemetry an attacker
//   // controls (prompt injection via command lines, file names, ...), so a
//   // human must review each one in the console; the console refuses
//   // AI-sourced approvals without the operator role. Rollouts change fleet
//   // policy and also need a human. Only list the rest, and approve one at a
//   // time after a person has read it (`reviewed` = ids a human confirmed):
//   for (const s of await w.suggestions()) {
//     if (s.source === "ai" || s.action.type === "rollout" || s.action.weakens || !s.can_approve) { console.log("review in console:", s.id, s.title); continue; }
//     console.log(s.id, s.title, s.rationale, s.evidence);
//     if (reviewed.has(s.id)) await w.decide(s.id, true, "reviewed by <name>");
//   }
//   console.log((await w.ask("Which hosts are not enforcing?")).answer);

export type Tier = "exploited" | "vulnerable" | "reachable" | "dormant" | "theoretical";
export interface Host { name: string; group: string; trust: string; cpu_pct: number; alerts: number; execs: number; runtimes: string[]; }
export interface Alert { ts: string; rule: string; severity: string; actor: string; actor_src: string; mitre?: string; title: string; host: string; cmd: string; }
export interface Finding { host: string; ecosystem: string; name: string; version: string; cve: string; severity: string; cvss: number; tier: Tier; note: string; }

export interface Incident { id: string; host: string; group: string; priority: "P1" | "P2" | "P3" | "P4"; score: number; severity: string; status: string;
  first_ts: string; last_ts: string; alert_count: number; rules: string[]; techniques: string[]; actors: string[]; campaign_hosts: string[];
  contained: boolean; summary: string; reasons: string[]; ai: { verdict: string; confidence: string; summary: string; ts: string } | null; }
/** "applying": approved and being carried out; "interrupted": the console stopped before the outcome was recorded (check the target). */
export type SuggestionStatus = "proposed" | "applying" | "applied" | "accepted" | "failed" | "rejected" | "expired" | "interrupted";
/** What approving a suggestion does. `weakens` is set on a curation change that would detect or stop less. */
export interface SuggestionAction { type?: "push" | "rollout" | "triage" | "manual" | string; weakens?: string; [k: string]: unknown; }
export interface Suggestion { id: string; ts: string; kind: string; title: string; rationale: string; severity: string; source: "analysis" | "ai";
  status: SuggestionStatus; action: SuggestionAction;
  /** The role needed to approve or reject it: deployer for an engine rollout, else operator (always at least operator when source is "ai"). */
  required_role: "operator" | "deployer" | string;
  /** Whether the caller's role may decide it (from GET /api/suggestions). */
  can_approve?: boolean;
  evidence: string[]; decided_by: string; decided_at: string; result: string; }
/** Pagination for suggestions(): newest first; limit 1..1000 (console default 500), offset from 0. */
export interface Page { limit?: number; offset?: number; }
/** POST /api/incidents/triage. `skipped`: alerts that joined the incident after it was shown, left as they were. */
export interface TriageResult { incident: string; status: string; updated: number; skipped: number; }
/** The full AI triage journal record returned by /api/incidents/detail (the list form flattens it to Incident["ai"]). */
export interface AiRecord { type: string; purpose: string; by: string; job: string; target: string; model: string;
  usage: Record<string, unknown>; result: { verdict?: string; confidence?: string; summary?: string; [k: string]: unknown }; ts: string; }
export type IncidentDetail = Omit<Incident, "ai"> & { ai: AiRecord | null; alerts: Alert[]; suggestions: Suggestion[] };

export class WispError extends Error {
  constructor(message: string, public readonly status?: number, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "WispError";
  }
}

export interface WispOptions {
  /** A fetch implementation, e.g. one bound to an undici Agent with a private CA. Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Allow sending the bearer token over plain http:// to a non-loopback host. Default false. */
  allowPlaintextToken?: boolean;
  /** Per-request timeout in ms (default 15000). */
  timeoutMs?: number;
}

function isLoopback(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\./.test(h);
}

export class Wisp {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(private base: string, private token?: string, opts: WispOptions = {}) {
    this.base = base.replace(/\/$/, "");
    const u = new URL(this.base);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new WispError("base URL must be http:// or https://");
    if (token && u.protocol === "http:" && !isLoopback(u.hostname) && !opts.allowPlaintextToken)
      throw new WispError(`refusing to send the bearer token over plain http to ${u.hostname}; use https://`);
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 15_000;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    let r: Response;
    try {
      r = await this.fetchImpl(this.base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs) });
    } catch (e) {
      const c = (e as { cause?: { code?: string; message?: string } })?.cause;  // undici puts the TLS/socket error here
      throw new WispError(`${method} ${path}: ${(e as Error)?.message ?? e}${c ? ` (${c.code ?? c.message})` : ""}`, undefined, { cause: e });
    }
    const text = await r.text();
    if (!r.ok) throw new WispError(`${r.status} ${r.statusText}: ${text}`, r.status);
    try {
      return (text ? JSON.parse(text) : null) as T;
    } catch (e) {
      throw new WispError(`${method} ${path}: invalid JSON response`, r.status, { cause: e });
    }
  }

  hosts()     { return this.req<Host[]>("GET", "/api/hosts"); }
  alerts()    { return this.req<Alert[]>("GET", "/api/alerts"); }
  inventory() { return this.req<any[]>("GET", "/api/inventory"); }
  vulns()     { return this.req<Finding[]>("GET", "/api/vulns"); }

  incidents(f: { status?: string; priority?: string; host?: string } = {}) {
    const q = new URLSearchParams(Object.entries(f).filter(([, v]) => v) as [string, string][]).toString();
    return this.req<Incident[]>("GET", `/api/incidents${q ? "?" + q : ""}`);
  }
  /** The AI verdict is at `.ai?.result.verdict` here (full journal record), unlike incidents(). */
  incident(id: string) { return this.req<IncidentDetail>("GET", `/api/incidents/detail?id=${encodeURIComponent(id)}`); }
  health()     { return this.req<{ status: string; findings: any[] }>("GET", "/api/analysis/health"); }
  ruleReview() { return this.req<any[]>("GET", "/api/analysis/rules"); }
  /** "" = waiting for approval (proposed or applying), "all" = everything, or one status. Newest first, one page. */
  suggestions(status: "" | "all" | SuggestionStatus = "", page: Page = {}) {
    const q = new URLSearchParams();
    if (status) q.set("status", status);
    if (page.limit !== undefined) q.set("limit", String(page.limit));
    if (page.offset !== undefined) q.set("offset", String(page.offset));
    const qs = q.toString();
    return this.req<Suggestion[]>("GET", `/api/suggestions${qs ? "?" + qs : ""}`);
  }
  /** Every suggestion with that status, fetched a page at a time (newest first). */
  async allSuggestions(status: "" | "all" | SuggestionStatus = "all", pageSize = 500): Promise<Suggestion[]> {
    const out: Suggestion[] = [];
    const seen = new Set<string>();
    for (let offset = 0; ; offset += pageSize) {
      const got = await this.suggestions(status, { limit: pageSize, offset });
      for (const s of got) if (!seen.has(s.id)) { seen.add(s.id); out.push(s); }
      if (got.length < pageSize) return out;
    }
  }
  /** Approve (the console carries it out) or reject. Operator; deployer for rollouts.
   *  Never call this in a loop over suggestions(): a human must review each one,
   *  above all AI-sourced ones (source === "ai"), which come from attacker-controllable
   *  telemetry. The console refuses AI-sourced approvals without the operator role. */
  decide(id: string, approve: boolean, note = "") {
    return this.req<Suggestion>("POST", "/api/suggestions/decide", { id, decision: approve ? "approve" : "reject", note });
  }
  /** Triage the alerts of an incident. Pass `alertIds`, the alerts a person reviewed (e.g. from incident(id).alerts):
   *  alerts that joined since are left alone (counted in `skipped`), and when none of them is in the incident any
   *  more the console answers 409 (WispError status 409: reload and review again). Without it, every alert is triaged. */
  triageIncident(id: string, status: "open" | "acknowledged" | "resolved", note = "", alertIds?: string[]) {
    const body: Record<string, unknown> = { id, status, note };
    if (alertIds) body["alert_ids"] = alertIds;
    return this.req<TriageResult>("POST", "/api/incidents/triage", body);
  }

  private async ai<T>(kind: string, body: unknown, timeoutMs: number): Promise<T> {
    let job = await this.req<any>("POST", `/api/ai/${kind}`, body);
    const end = Date.now() + timeoutMs;
    let failures = 0;
    while (job.status === "queued" || job.status === "running") {
      if (Date.now() > end) throw new WispError(`AI job ${job.id} still ${job.status}`);
      await new Promise((r) => setTimeout(r, 1000));
      try {
        job = await this.req<any>("GET", `/api/ai/jobs?id=${encodeURIComponent(job.id)}`);
        failures = 0;
      } catch (e) {
        const st = e instanceof WispError ? e.status : undefined;
        if ((st !== undefined && st < 500) || ++failures >= 5)
          throw new WispError(`AI job ${job.id}: polling failed: ${(e as Error).message}`, st, { cause: e });
      }
    }
    if (job.status !== "done") throw new WispError(`AI job ${job.id}: ${job.error || "AI job failed"}`);
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
