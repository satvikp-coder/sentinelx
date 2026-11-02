/**
 * Live Shield - shows shield rules, their TTL, and mode.
 * Shield rules are TEMPORARY SHIELD, NOT A FIX.
 */

import React, { useEffect, useState } from "react";
import { api, ShieldRuleData } from "../api";
import { LabelChip } from "../components/LabelChip";

export function LiveShield() {
  const [rules, setRules] = useState<ShieldRuleData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listShieldRules().then(setRules).catch((e) => setError(e instanceof Error ? e.message : "unknown error")).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Live Shield</h2>
        <p className="text-gray-600">
          Temporary shield rules block malicious traffic at the reverse proxy.
          <strong>TEMPORARY SHIELD, NOT A FIX</strong> - they buy time for a human.
        </p>
      </div>

      <div className="bg-amber-50 border border-amber-100 rounded-lg p-3 mb-4">
        <p className="text-sm text-amber-800">
          Shield rules are narrow, time-limited, and never edit code. They expire
          automatically based on TTL. Only an applied, verified patch is a fix.
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">Error: {error}</p>
        </div>
      )}

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Active Shield Rules</h3>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading...</div>
        ) : rules.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No shield rules active.</div>
        ) : (
          <div className="divide-y divide-gray-100">
            {rules.map((r) => (
              <div key={r.rule_id} className="p-2 border-b border-gray-50 last:border-0">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-sm font-medium text-gray-800">{r.route_pattern}</div>
                    <div className="text-xs text-gray-500">Intent: {r.intent} | Mode: {r.mode}</div>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <LabelChip label={r.state.toUpperCase()} />
                    <LabelChip label="TEMPORARY" />
                  </div>
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  TTL: {r.ttl_minutes} min | Created: {r.created_at} | Expires: {r.expires_at ?? "not set"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
