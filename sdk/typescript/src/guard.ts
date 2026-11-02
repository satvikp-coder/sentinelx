/**
 * Sentinel X Agent Guard - TypeScript SDK.
 *
 * Every tool call is checked by the sidecar policy gateway BEFORE the tool runs.
 * In enforce mode, a blocked action MUST NEVER execute the wrapped tool (fail-closed).
 * In monitor mode, the tool executes regardless, but the decision is logged.
 */

import { GuardBlockedError, GuardClientError, GuardConfigError } from "./errors";
import {
  GuardAction,
  GuardCheckOptions,
  GuardConfig,
  GuardDecisionResult,
  GuardMode,
  GuardOutcome,
  ValidatedDecision,
} from "./types";
import { SidecarClient } from "./client";

const TOOL_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;

/** Validate a tool name against the allowed pattern. */
function validateToolName(tool: unknown): string {
  if (typeof tool !== "string" || !TOOL_NAME_RE.test(tool)) {
    throw new GuardConfigError(`invalid tool name: ${String(tool)}`);
  }
  return tool;
}

/** Validate a GuardConfig object. */
function validateConfig(config: unknown): asserts config is GuardConfig {
  if (!config || typeof config !== "object") {
    throw new GuardConfigError("Guard config must be an object");
  }
  const c = config as Record<string, unknown>;
  if (typeof c["baseUrl"] !== "string" || !c["baseUrl"]) {
    throw new GuardConfigError('config.baseUrl must be a non-empty string');
  }
  if (typeof c["token"] !== "string" || !c["token"]) {
    throw new GuardConfigError('config.token must be a non-empty string');
  }
  if (c["mode"] !== "monitor" && c["mode"] !== "enforce") {
    throw new GuardConfigError('config.mode must be "monitor" or "enforce"');
  }
  if (
    c["timeoutMs"] !== undefined &&
    (typeof c["timeoutMs"] !== "number" || c["timeoutMs"] <= 0)
  ) {
    throw new GuardConfigError("config.timeoutMs must be a positive number");
  }
  if (c["approver"] !== undefined && typeof c["approver"] !== "function") {
    throw new GuardConfigError("config.approver must be a function");
  }
}

/** Validate a GuardAction object. */
function validateAction(action: unknown): asserts action is GuardAction {
  if (!action || typeof action !== "object") {
    throw new GuardConfigError("action must be an object");
  }
  const a = action as Record<string, unknown>;
  validateToolName(a["tool"]);
  if (
    !a["arguments"] ||
    typeof a["arguments"] !== "object" ||
    Array.isArray(a["arguments"])
  ) {
    throw new GuardConfigError('action.arguments must be an object');
  }
}

/**
 * Validate and normalize a sidecar decision into a ValidatedDecision.
 * Rejects extra/missing fields so the decision path is deterministic.
 */
function validateDecision(raw: GuardDecisionResult): ValidatedDecision {
  const decision = raw.decision;
  if (decision !== "ALLOW" && decision !== "BLOCK" && decision !== "CONFIRM") {
    throw new GuardClientError(`invalid decision from sidecar: ${decision}`);
  }
  if (typeof raw.reasonCode !== "string" || !raw.reasonCode) {
    throw new GuardClientError("invalid reasonCode from sidecar");
  }
  if (!Array.isArray(raw.ruleIds) || !raw.ruleIds.every((r) => typeof r === "string")) {
    throw new GuardClientError("invalid ruleIds from sidecar");
  }
  if (typeof raw.requiresHuman !== "boolean") {
    throw new GuardClientError("invalid requiresHuman from sidecar");
  }
  if (typeof raw.explanation !== "string") {
    throw new GuardClientError("invalid explanation from sidecar");
  }
  return {
    decision,
    reasonCode: raw.reasonCode,
    ruleIds: raw.ruleIds,
    blocked: decision === "BLOCK",
    requiresHuman: decision === "CONFIRM",
    explanation: raw.explanation,
  };
}

/**
 * The Guard: wraps tool calls with policy enforcement via the sidecar API.
 *
 * Critical invariant: in enforce mode, a blocked action MUST NEVER execute
 * the wrapped tool. GuardBlockedError is thrown before the tool body runs.
 */
export class Guard {
  private readonly client: SidecarClient;
  private readonly mode: GuardMode;
  private readonly approver?: (action: GuardAction) => boolean | Promise<boolean>;

  constructor(config: GuardConfig) {
    validateConfig(config);
    this.client = new SidecarClient(config);
    this.mode = config.mode;
    this.approver = config.approver;
  }

  /**
   * Check a single action against the sidecar policy gateway.
   * Returns a GuardDecisionResult. Does NOT execute any tool.
   * Throws GuardClientError if the sidecar is unreachable (fail-closed in enforce mode).
   */
  async check(options: GuardCheckOptions): Promise<GuardDecisionResult> {
    validateAction(options.action);
    if (typeof options.sessionId !== "string" || !options.sessionId) {
      throw new GuardConfigError("sessionId must be a non-empty string");
    }

    const raw = await this.client.decide(
      options.sessionId,
      options.action.tool,
      options.action.arguments,
    );
    return validateDecision(raw);
  }

  /**
   * Wrap a tool function so that every call is checked by the guard first.
   *
   * @param toolName - name of the tool (validated)
   * @param fn - the tool function to wrap
   * @returns a wrapped function that checks the guard before executing
   *
   * Behavior:
   * - monitor mode: decision is recorded, tool always executes
   * - enforce mode ALLOW: tool executes
   * - enforce mode BLOCK: throws GuardBlockedError, tool NEVER executes
   * - enforce mode CONFIRM: calls approver; if approved, tool executes;
   *   if not approved, throws GuardBlockedError
   * - Sidecar failure: throws GuardClientError (fail-closed, tool never executes)
   */
  tool<TArgs extends unknown[], TReturn>(
    toolName: string,
    fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  ): (...args: TArgs) => Promise<TReturn> {
    validateToolName(toolName);

    return async (...args: TArgs): Promise<TReturn> => {
      // Build the action from the function arguments. We use positional argument
      // names from the wrapped function if available, otherwise "arg0", "arg1", etc.
      const arguments_: Record<string, unknown> = {};
      for (let i = 0; i < args.length; i++) {
        arguments_[`arg${i}`] = args[i];
      }

      const action: GuardAction = { tool: toolName, arguments: arguments_ };

      // We need a sessionId. Use a default if none provided by the caller.
      // The wrapped function signature doesn't include sessionId, so we use
      // a sentinel. Callers needing per-session tracking should use check() directly.
      const sessionId = "sdk-default";

      let decision: GuardDecisionResult;
      try {
        decision = await this.check({ sessionId, action });
      } catch (e) {
        // Sidecar failure -> fail-closed: never execute the tool
        if (e instanceof GuardClientError) {
          throw new GuardBlockedError(toolName, "BLOCK", "sidecar_unavailable");
        }
        throw e;
      }

      const validated = validateDecision(decision);

      if (this.mode === "monitor") {
        // Monitor mode: record decision but always execute
        return fn(...args);
      }

      // Enforce mode
      if (validated.decision === "ALLOW") {
        return fn(...args);
      }

      if (validated.decision === "BLOCK") {
        throw new GuardBlockedError(
          toolName,
          "BLOCK",
          validated.reasonCode,
        );
      }

      // CONFIRM: ask the approver
      if (validated.decision === "CONFIRM") {
        let approved = false;
        if (this.approver) {
          try {
            approved = await this.approver(action);
          } catch {
            approved = false;
          }
        }
        if (!approved) {
          throw new GuardBlockedError(
            toolName,
            "BLOCK",
            "confirm_not_approved",
          );
        }
        // Re-check after approval (approver may have changed state)
        try {
          const recheck = await this.check({ sessionId, action });
          const revalidated = validateDecision(recheck);
          if (revalidated.decision !== "ALLOW") {
            throw new GuardBlockedError(
              toolName,
              revalidated.decision,
              revalidated.reasonCode,
            );
          }
        } catch (e) {
          if (e instanceof GuardBlockedError) throw e;
          if (e instanceof GuardClientError) {
            throw new GuardBlockedError(toolName, "BLOCK", "recheck_failed");
          }
          throw e;
        }
        return fn(...args);
      }

      // Should be unreachable (decision is validated)
      throw new GuardBlockedError(toolName, "BLOCK", "unknown_decision");
    };
  }

  /**
   * Convenience: check + execute pattern. Returns a GuardOutcome discriminated
   * union so callers can handle allowed/blocked/confirm-required explicitly.
   * The tool is NOT executed by this method; the caller decides based on outcome.
   */
  async checkAndDecide(options: GuardCheckOptions): Promise<GuardOutcome> {
    validateAction(options.action);
    if (typeof options.sessionId !== "string" || !options.sessionId) {
      throw new GuardConfigError("sessionId must be a non-empty string");
    }

    let decision: GuardDecisionResult;
    try {
      decision = await this.check(options);
    } catch (e) {
      if (e instanceof GuardClientError) {
        const blocked: GuardDecisionResult = {
          decision: "BLOCK",
          reasonCode: "sidecar_unavailable",
          ruleIds: [],
          requiresHuman: false,
          explanation: "sidecar unavailable; fail-closed",
        };
        const error = new GuardBlockedError(
          options.action.tool,
          "BLOCK",
          "sidecar_unavailable",
        );
        return { kind: "blocked", decision: blocked, error };
      }
      throw e;
    }

    const validated = validateDecision(decision);

    if (validated.blocked) {
      const error = new GuardBlockedError(
        options.action.tool,
        "BLOCK",
        validated.reasonCode,
      );
      return { kind: "blocked", decision, error };
    }

    if (validated.requiresHuman) {
      return { kind: "confirm-required", decision };
    }

    return { kind: "allowed", decision };
  }
}
