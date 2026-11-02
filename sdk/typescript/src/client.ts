/**
 * Sidecar API client for the Sentinel X TypeScript SDK.
 *
 * Talks to the local /api/v1 backend (http://127.0.0.1 only).
 * All responses are validated; network failures are surfaced as GuardClientError.
 */

import { GuardClientError } from "./errors";
import { GuardConfig, GuardDecision, GuardDecisionResult } from "./types";

const ALLOWED_HOST_PREFIXES = ["http://127.0.0.1", "http://localhost"];

/**
 * Validate that a base URL is local-only. Rejects any public or remote URL.
 */
function validateBaseUrl(baseUrl: string): void {
  try {
    const url = new URL(baseUrl);
    if (
      !ALLOWED_HOST_PREFIXES.some((p) => url.href.startsWith(p + "/") || url.href === p)
    ) {
      throw new GuardClientError(
        `Sidecar base URL must be local (127.0.0.1 or localhost), got: ${baseUrl}`,
      );
    }
  } catch (e) {
    if (e instanceof GuardClientError) throw e;
    throw new GuardClientError(`Invalid sidecar base URL: ${baseUrl}`);
  }
}

/**
 * Raw sidecar API decision response (before validation).
 */
interface RawSidecarDecision {
  decision: string;
  reason_code: string;
  rule_ids: string[];
  requires_human: boolean;
  explanation: string;
}

/**
 * Sidecar API client. Thin wrapper over fetch with local-only URL enforcement,
 * timeouts, and response validation.
 */
export class SidecarClient {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;

  constructor(config: GuardConfig) {
    validateBaseUrl(config.baseUrl);
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.token = config.token;
    this.timeoutMs = config.timeoutMs ?? 5000;
  }

  /**
   * POST /api/v1/guard/decide - ask the sidecar for a policy decision.
   * Throws GuardClientError on network failure, invalid response, or non-2xx.
   */
  async decide(
    sessionId: string,
    tool: string,
    arguments_: Record<string, unknown>,
  ): Promise<GuardDecisionResult> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const resp = await fetch(`${this.baseUrl}/api/v1/guard/decide`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          session_id: sessionId,
          tool,
          arguments: arguments_,
        }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        let detail = "";
        try {
          const body = await resp.json();
          detail = body.detail || body.error || String(resp.status);
        } catch {
          detail = String(resp.status);
        }
        throw new GuardClientError(
          `Sidecar API returned ${resp.status}: ${detail}`,
          resp.status,
          detail,
        );
      }

      const json: RawSidecarDecision = await resp.json();

      // Validate the shape of the response (extra fields are ignored here;
      // the Guard class performs stricter validation).
      if (
        typeof json.decision !== "string" ||
        typeof json.reason_code !== "string" ||
        !Array.isArray(json.rule_ids) ||
        typeof json.requires_human !== "boolean" ||
        typeof json.explanation !== "string"
      ) {
        throw new GuardClientError("Sidecar returned a malformed decision response");
      }

      const decision = json.decision as GuardDecision;
      if (decision !== "ALLOW" && decision !== "BLOCK" && decision !== "CONFIRM") {
        throw new GuardClientError(`Sidecar returned unknown decision: ${decision}`);
      }

      return {
        decision,
        reasonCode: json.reason_code,
        ruleIds: json.rule_ids,
        requiresHuman: json.requires_human,
        explanation: json.explanation,
      };
    } catch (e) {
      if (e instanceof GuardClientError) throw e;
      if (e instanceof DOMException && e.name === "AbortError") {
        throw new GuardClientError(`Sidecar request timed out after ${this.timeoutMs}ms`);
      }
      throw new GuardClientError(
        `Sidecar request failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
