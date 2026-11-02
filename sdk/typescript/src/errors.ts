/** Errors thrown by the Sentinel X TypeScript Agent Guard SDK. */

import { GuardDecision } from "./types";

/**
 * Thrown when the guard blocks a tool call in enforce mode.
 * The wrapped tool MUST NOT execute when this error is thrown.
 */
export class GuardBlockedError extends Error {
  public readonly tool: string;
  public readonly decision: GuardDecision;
  public readonly reasonCode: string;

  constructor(tool: string, decision: GuardDecision, reasonCode: string) {
    super(`Guard blocked tool ${tool}: decision=${decision} reason=${reasonCode}`);
    this.name = "GuardBlockedError";
    this.tool = tool;
    this.decision = decision;
    this.reasonCode = reasonCode;
  }
}

/**
 * Thrown when the sidecar API is unreachable or returns an invalid response.
 * In enforce mode this causes a fail-closed (blocked) outcome.
 */
export class GuardClientError extends Error {
  public readonly statusCode?: number;
  public readonly body?: string;

  constructor(message: string, statusCode?: number, body?: string) {
    super(message);
    this.name = "GuardClientError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

/**
 * Thrown when the SDK configuration is invalid.
 */
export class GuardConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardConfigError";
  }
}
