/**
 * Fix Verification and Human Approval - shows fix proposals awaiting approval.
 * No fix is auto-applied; human approval is required.
 */

import React, { useEffect, useState } from "react";
import { api, FindingData } from "../api";
import { LabelChip } from "../components/LabelChip";

export function FixVerification() {
  const [findings, setFindings] = useState<FindingData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listFindings().then(setFindings).catch((e) => setError(e instanceof Error ? e.message : "unknown error")).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Fix Verification & Human Approval</h2>
        <p className="text-gray-600">
          Fix proposals are independently verified before any human approval.
          No fix is auto-applied - a shield rule is NOT a fix.
        </p>
      </div>

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Pending Fix Proposals</h3>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading...</div>
        ) : findings.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No fix proposals pending.</div>
        ) : (
          <div className="divide-y divide-gray-100">
            {findings.map((f) => (
              <div key={f.id} className="p-3 border-b border-gray-50 last:border-0">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-sm font-medium text-gray-800">{f.id}</div>
                    <div className="text-xs text-gray-500">{f.summary}</div>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <LabelChip label={f.state.toUpperCase()} />
                    <LabelChip label={f.severity.toUpperCase()} />
                    <LabelChip label={f.mode} />
                  </div>
                </div>
                <div className="mt-2 text-xs text-gray-500">
                  Session: {f.session_id} | Created: {f.created_at}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-amber-50 border border-amber-100 rounded-lg p-3">
        <p className="text-sm text-amber-800">
          <strong>Approval required:</strong> Any fix that changes code requires
          human approval. The gateway re-evaluates after approval. Shield rules
          are temporary - only an applied, verified patch is a fix.
        </p>
      </div>
    </div>
  );
}
