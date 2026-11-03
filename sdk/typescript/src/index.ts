/**
 * Sentinel X TypeScript Agent Guard SDK.
 *
 * Public API:
 *   - Guard: policy-enforced wrapper for agent tools
 *   - GuardBlockedError: thrown when a tool call is blocked
 *   - GuardClientError: thrown when the sidecar API is unreachable
 *   - GuardConfigError: thrown when configuration is invalid
 *   - SidecarClient: low-level sidecar API client
 *   - Types: GuardConfig, GuardAction, GuardDecisionResult, GuardMode,
 *     GuardDecision, GuardOutcome, ValidatedDecision
 */

export { Guard } from "./guard";
export { GuardBlockedError, GuardClientError, GuardConfigError } from "./errors";
export { SidecarClient } from "./client";

export type {
  GuardConfig,
  GuardAction,
  GuardDecisionResult,
  GuardMode,
  GuardDecision,
  GuardOutcome,
  ValidatedDecision,
  GuardCheckOptions,
} from "./types";
