/**
 * Sentinel X Mission Control - API service layer.
 *
 * All calls go to the local /api/v1 backend. No public targets, no invented metrics.
 * Every number displayed comes from backend-derived data only.
 */

declare global {
  interface Window {
    SENTINELX_API_BASE_URL?: string;
    SENTINELX_DEMO_TOKEN?: string;
  }
}
// Optional operator configuration loaded before the bundle; never a provider key.
const endpoint = new URL(window.SENTINELX_API_BASE_URL ?? "http://127.0.0.1:8080");
if (endpoint.protocol !== "http:" || !["127.0.0.1", "localhost"].includes(endpoint.hostname)
    || endpoint.username || endpoint.password || endpoint.search || endpoint.hash
    || endpoint.pathname !== "/") {
  throw new Error("The local demo API requires a loopback HTTP origin");
}
const BASE_URL = endpoint.origin;
const DEMO_TOKEN = window.SENTINELX_DEMO_TOKEN ?? "sentinelx-demo-local-only";

export type LabelMode = "LIVE" | "RECORDED" | "SIMULATED";

export interface HealthData {
  status: string;
  version: string;
  mode: LabelMode;
  model_available: boolean;
  features: string[];
}

export interface SessionData {
  id: string;
  scenario_id: string;
  lab: string;
  arm: string;
  label: string | null;
  state: string;
  created_at: string;
  updated_at: string;
}

export interface RunData {
  id: string;
  session_id: string;
  arm: string;
  state: string;
  model_mode: LabelMode;
  created_at: string;
  updated_at: string;
  steps: number;
  actions_attempted: number;
  actions_executed: number;
  actions_blocked: number;
}

export interface EventData {
  id: string;
  seq: number;
  run_id: string | null;
  kind: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface PolicyDecision {
  decision: string;
  reason_code: string;
  rule_ids: string[];
  requires_human: boolean;
  explanation: string;
}

export interface Metric {
  name: string;
  numerator: number;
  denominator: number;
  value: number | null;
}

export interface MetricsData {
  arm: string;
  metrics: Metric[];
}

export interface FindingData {
  id: string;
  session_id: string;
  state: string;
  severity: string;
  summary: string;
  mode: LabelMode;
  model_provider: string | null;
  model_name: string | null;
  created_at: string;
}

export interface ShieldRuleData {
  rule_id: string;
  route_pattern: string;
  intent: string;
  mode: string;
  state: string;
  ttl_minutes: number;
  created_at: string;
  expires_at: string | null;
}

export interface GuardDecision {
  decision: string;
  reasonCode: string;
  ruleIds: string[];
  requiresHuman: boolean;
  explanation: string;
  blocked: boolean;
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  opts: RequestInit = {},
): Promise<T> {
  const resp = await fetch(`${BASE_URL}${path}`, {
    ...opts,
    credentials: "include",
    headers: {
      Authorization: `Bearer ${DEMO_TOKEN}`,
      "Content-Type": "application/json",
      ...opts.headers,
    },
  });
  if (!resp.ok) {
    let detail = "";
    try {
      const body = await resp.json();
      detail = body.detail || body.error || String(resp.status);
    } catch {
      detail = String(resp.status);
    }
    throw new ApiError(resp.status, detail);
  }
  if (resp.status === 204) return undefined as T;
  return resp.json();
}

export const api = {
  health: (): Promise<HealthData> => request("/health"),

  listSessions: (): Promise<SessionData[]> =>
    request("/api/v1/sessions"),
  createSession: (body: {
    scenario_id: string; lab: string; arm: string; label?: string;
  }) => request<SessionData>("/api/v1/sessions", {
    method: "POST", body: JSON.stringify(body),
  }),
  getSession: (id: string): Promise<SessionData> =>
    request(`/api/v1/sessions/${id}`),

  listRuns: (): Promise<RunData[]> => request("/api/v1/runs"),
  createRun: (body: { session_id: string; arm: string; model_mode?: LabelMode }) =>
    request<RunData>("/api/v1/runs", { method: "POST", body: JSON.stringify(body) }),
  cancelRun: (id: string): Promise<{ run_id: string; state: string }> =>
    request(`/api/v1/runs/${id}/cancel`, { method: "POST" }),

  listEvents: (): Promise<EventData[]> => request("/api/v1/events"),
  createSSESession: () =>
    request("/api/v1/events/session", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${DEMO_TOKEN}`,
      },
    }),
  eventStream: (onEvent: (event: EventData) => void, afterSeq = 0) => {
    const es = new EventSource(
      `${BASE_URL}/api/v1/events/stream?after_seq=${afterSeq}`,
      { withCredentials: true },
    );
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as EventData;
        onEvent(data);
      } catch {
        // ignore malformed events
      }
    };
    // EventSource reconnects with Last-Event-ID; cleanup closes it on unmount.
    return () => es.close();
  },

  policyDecide: (body: { session_id: string; tool: string; arguments?: Record<string, unknown>; allowed_hosts?: string[] }) =>
    request<PolicyDecision>("/api/v1/policy/decide", {
      method: "POST", body: JSON.stringify(body),
    }),

  listFindings: (): Promise<FindingData[]> => request("/api/v1/findings"),

  listMetrics: (arm?: string): Promise<MetricsData> => {
    const qs = arm ? `?arm=${arm}` : "";
    return request<MetricsData>(`/api/v1/metrics${qs}`);
  },

  listTargets: (): Promise<Array<{
    target_id: string; url: string; lab: boolean; owned: boolean;
  }>> => request("/api/v1/targets"),
  addTarget: (body: { target_id: string; url: string; lab?: boolean }) =>
    request("/api/v1/targets", { method: "POST", body: JSON.stringify(body) }),

  createScan: (body: { target_id: string; model?: boolean }) =>
    request<{ scan_id: string; state: string; findings_count: number }>("/api/v1/scans", {
      method: "POST", body: JSON.stringify(body),
    }),

  shieldEvidence: () => request<{ok: boolean; chain_status: string; events_checked: number;
    events: Array<{id: string; kind: string; state: string; timestamp_utc: string}>}>("/api/v1/shield/evidence"),
  listShieldRules: (): Promise<ShieldRuleData[]> => request("/api/v1/shield/rules"),
  createShieldRule: (body: { route_pattern: string; intent: string; mode: string; ttl_minutes: number; reason: string }) =>
    request<ShieldRuleData>("/api/v1/shield/rules", {
      method: "POST", body: JSON.stringify(body),
    }),
  approveShieldRule: (id: string, sessionId: string) =>
    request<ShieldRuleData>(`/api/v1/shield/rules/${id}/approve`, {
      method: "POST", body: JSON.stringify({session_id: sessionId, action_id: id, tool: "shield_rule"}),
    }),
  recordShieldApproval: (id: string, sessionId: string) =>
    request("/api/v1/approvals", {
      method: "POST", body: JSON.stringify({session_id: sessionId, action_id: id,
        tool: "shield_rule", arguments: {}, reviewer: "local-demo-operator",
        rationale: "Human approved this displayed temporary rule", decision: "approve"}),
    }),
  removeShieldRule: (id: string) =>
    request(`/api/v1/shield/rules/${id}`, { method: "DELETE" }),
  expireShieldRule: (id: string) =>
    request(`/api/v1/shield/rules/${id}/expire`, { method: "POST" }),

  guardDecide: (body: { session_id: string; tool: string; arguments?: Record<string, unknown> }) =>
    request<{ decision: string; reason_code: string; rule_ids: string[]; requires_human: boolean; explanation: string }>("/api/v1/guard/decide", {
      method: "POST", body: JSON.stringify(body),
    }).then((d) => ({
      decision: d.decision as "ALLOW" | "BLOCK" | "CONFIRM",
      reasonCode: d.reason_code,
      ruleIds: d.rule_ids,
      requiresHuman: d.requires_human,
      explanation: d.explanation,
      blocked: d.decision === "BLOCK",
    })),

  exportReport: () => request("/api/v1/reports/export"),
  listEscalations: () => request<Array<{
    ticket_id: string; finding_id: string; state: string; reason: string; created_at: string;
  }>>("/api/v1/escalations"),
};

export { ApiError };
