/**
 * Paired Run Comparator - compares unprotected vs protected run outcomes.
 * Shows attempted vs executed actions with numerators and denominators.
 */

import React, { useEffect, useState } from "react";
import { api, RunData } from "../api";
import { MetricCard } from "../components/MetricCard";
import { LabelChip } from "../components/LabelChip";

export function PairedRunComparator() {
  const [runs, setRuns] = useState<RunData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listRuns().then(setRuns).catch((e) => setError(e instanceof Error ? e.message : "unknown error")).finally(() => setLoading(false));
  }, []);

  const armA = runs.filter((r) => r.arm === "A");
  const armB = runs.filter((r) => r.arm === "B");

  const computeStats = (rs: RunData[]) => {
    const attempted = rs.reduce((sum, r) => sum + r.actions_attempted, 0);
    const executed = rs.reduce((sum, r) => sum + r.actions_executed, 0);
    const blocked = rs.reduce((sum, r) => sum + r.actions_blocked, 0);
    return { attempted, executed, blocked };
  };

  const statsA = computeStats(armA);
  const statsB = computeStats(armB);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Paired Run Comparator</h2>
        <p className="text-gray-600">
          Compare arm A (unprotected) vs arm B (protected) run outcomes.
          Attempted vs executed actions are distinguished - a blocked action was
          ATTEMPTED, not EXECUTED.
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">Error: {error}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white border rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">
            <LabelChip label="ARM A - UNPROTECTED" /> Arm A
          </h3>
          <div className="space-y-3">
            <MetricCard metric={{ name: "actions_attempted", numerator: statsA.attempted, denominator: statsA.attempted || 1, value: 1 }} labelSuffix="total attempted" />
            <MetricCard metric={{ name: "actions_executed", numerator: statsA.executed, denominator: statsA.attempted || 1, value: statsA.attempted > 0 ? statsA.executed / statsA.attempted : 0 }} labelSuffix="executed rate" />
            <MetricCard metric={{ name: "actions_blocked", numerator: statsA.blocked, denominator: statsA.attempted || 1, value: statsA.attempted > 0 ? statsA.blocked / statsA.attempted : 0 }} labelSuffix="blocked rate" />
          </div>
          <div className="mt-3 text-xs text-gray-500">
            {armA.length} runs in arm A
          </div>
        </div>

        <div className="bg-white border rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">
            <LabelChip label="ARM B - PROTECTED" /> Arm B
          </h3>
          <div className="space-y-3">
            <MetricCard metric={{ name: "actions_attempted", numerator: statsB.attempted, denominator: statsB.attempted || 1, value: 1 }} labelSuffix="total attempted" />
            <MetricCard metric={{ name: "actions_executed", numerator: statsB.executed, denominator: statsB.attempted || 1, value: statsB.attempted > 0 ? statsB.executed / statsB.attempted : 0 }} labelSuffix="executed rate" />
            <MetricCard metric={{ name: "actions_blocked", numerator: statsB.blocked, denominator: statsB.attempted || 1, value: statsB.attempted > 0 ? statsB.blocked / statsB.attempted : 0 }} labelSuffix="blocked rate" />
          </div>
          <div className="mt-3 text-xs text-gray-500">
            {armB.length} runs in arm B
          </div>
        </div>
      </div>

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Run Details</h3>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading runs...</div>
        ) : runs.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No runs recorded yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200 text-left">
                  <th className="pb-2 text-gray-600">Run ID</th>
                  <th className="pb-2 text-gray-600">Arm</th>
                  <th className="pb-2 text-gray-600">State</th>
                  <th className="pb-2 text-gray-600">Attempted</th>
                  <th className="pb-2 text-gray-600">Executed</th>
                  <th className="pb-2 text-gray-600">Blocked</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id} className="border-b border-gray-50 last:border-0">
                    <td className="py-2 font-mono text-xs">{r.id}</td>
                    <td className="py-2">
                      <LabelChip label={`ARM ${r.arm}`} />
                    </td>
                    <td className="py-2">{r.state}</td>
                    <td className="py-2">{r.actions_attempted}</td>
                    <td className="py-2">{r.actions_executed}</td>
                    <td className="py-2">{r.actions_blocked}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
