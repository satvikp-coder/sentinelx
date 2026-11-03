/**
 * Evaluation Metrics and Reports - shows benchmark results with numerators
 * and denominators. Never invents metrics.
 */

import React, { useEffect, useState } from "react";
import { api, MetricsData } from "../api";
import { MetricCard } from "../components/MetricCard";
import { LabelChip } from "../components/LabelChip";

export function EvaluationMetrics() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [arm, setArm] = useState("A");

  useEffect(() => {
    api.listMetrics(arm).then(setMetrics).catch((e) => setError(e instanceof Error ? e.message : "unknown error")).finally(() => setLoading(false));
  }, [arm]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Evaluation Metrics & Reports</h2>
        <p className="text-gray-600">
          All metrics show raw numerators and denominators. No fabricated numbers.
          Labels show SIMULATED / RECORDED / LIVE provenance.
        </p>
      </div>

      <div className="flex items-center gap-3">
        <label className="text-sm text-gray-700">Arm:</label>
        <button
          onClick={() => setArm("A")}
          className={`px-3 py-1 rounded text-sm border ${arm === "A" ? "bg-blue-100 text-blue-800 border-blue-200" : "bg-white text-gray-600 border-gray-200"}`}
        >
          A
        </button>
        <button
          onClick={() => setArm("B")}
          className={`px-3 py-1 rounded text-sm border ${arm === "B" ? "bg-blue-100 text-blue-800 border-blue-200" : "bg-white text-gray-600 border-gray-200"}`}
        >
          B
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">Error: {error}</p>
        </div>
      )}

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Metrics</h3>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading...</div>
        ) : !metrics ? (
          <div className="text-center py-4 text-gray-500">No metrics available.</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {metrics.metrics.map((m) => (
              <MetricCard key={m.name} metric={m} labelSuffix={`arm ${arm}`} />
            ))}
          </div>
        )}
      </div>

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Report Export</h3>
        <p className="text-sm text-gray-600 mb-3">
          Export the full evaluation report as JSON. Generated from backend data only.
        </p>
        <button
          onClick={async () => {
            try {
              const report = await api.exportReport();
              const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "sentinelx-report.json";
              a.click();
              URL.revokeObjectURL(url);
            } catch (e) {
              setError(e instanceof Error ? e.message : "unknown error");
            }
          }}
          className="bg-blue-600 text-white px-4 py-2 rounded text-sm hover:bg-blue-700"
        >
          Export Report (JSON)
        </button>
      </div>
    </div>
  );
}
