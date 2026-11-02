/**
 * Strict TypeScript types for the Sentinel X Agent Guard SDK.
 *
 * All types are nominally typed where possible and forbid excess properties
 * to prevent accidental data leakage into the guard decision path.
 */

export type GuardMode = "monitor" | "enforce";

export type GuardDecision = "ALLOW" | "BLOCK" | "CONFIRM";

export type LabelMode = "LIVE" | "RECORDED" | "SIMULATED";

export interface GuardConfig {
  /** Sidecar API base URL (must be http://127.0.0.1 or http://localhost). */
  baseUrl: string;
  /** Demo bearer token for the local API. */
  token: string;
  /** Operating mode: monitor (log only) or enforce (block). */
  mode: GuardMode;
  /** Request timeout in milliseconds. Default: 5000. */
  timeoutMs?: number;
  /** Approver callback for CONFIRM decisions (enforce mode only). */
  approver?: (action: GuardAction) => boolean | Promise<boolean>;
}

export interface GuardAction {
  tool: string;
  arguments: Record<string, unknown>;
}

export interface GuardDecisionResult {
  decision: GuardDecision;
  reasonCode: string;
  ruleIds: string[];
  requiresHuman: boolean;
  explanation: string;
}

/**
 * Validated sidecar API response. Extra properties are rejected by the
 * constructor to prevent unexpected fields from influencing decisions.
 */
export interface ValidatedDecision {
  decision: GuardDecision;
  reasonCode: string;
  ruleIds: string[];
  blocked: boolean;   // true iff decision === "BLOCK"
  requiresHuman: boolean; // true iff decision === "CONFIRM"
  explanation: string;
}

export interface GuardCheckOptions {
  sessionId: string;
  action: GuardAction;
}

export interface GuardToolWrapperOptions extends GuardCheckOptions {
  /** Tool name for error messages. */
  toolName: string;
}

/**
 * Brand type for session IDs to prevent mixing with other string IDs.
 */
export type SessionId = string & { readonly __brand: unique symbol };

/**
 * Brand type for tool names.
 */
export type ToolName = string & { readonly __brand: unique symbol };

// Discriminated union: a validated decision always carries enough info
// to determine whether execution is permitted.
export type GuardOutcome =
  | { kind: "allowed"; decision: GuardDecisionResult }
  | { kind: "blocked"; decision: GuardDecisionResult; error: Error }
  | { kind: "confirm-required"; decision: GuardDecisionResult };
