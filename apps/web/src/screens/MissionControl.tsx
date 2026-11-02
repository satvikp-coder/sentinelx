/**
 * Mission Control - top-level overview showing health, key metrics, and recent events.
 * All data comes from the backend API. Nothing is invented.
 */

import React, { useEffect, useState } from "react";
import { useApi } from "../contexts/ApiContext";
import { api, Metric } from "../api";
import { LabelChip } from "../components/LabelChip";
import { MetricCard } from "../components/MetricCard";

export function MissionControl() {
  const { health, healthLoading, healthError, refreshHealth, events, eventsLoading } = useApi();
  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsError, setMetricsError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      setMetricsLoading(true);
      try {
        const data = await api.listMetrics("A");
        setMetrics(data.metrics);
      } catch (e) {
        setMetricsError(e instanceof Error ? e.message : "unknown error");
      } finally {
        setMetricsLoading(false);
      }
    }
    load();
  }, []);

  if (healthLoading) {
    return <div className="text-center py-20 text-gray-500">Loading Mission Control...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Mission Control</h2>
        <p className="text-gray-600">Central overview of Sentinel X system status. All data from backend API.</p>
      </div>

      {/* Health status */}
      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-2">System Health</h3>
        {healthError ? (
          <div className="text-xs text-red-600">{healthError}</div>
        ) : (
          <div className="flex items-center gap-4">
            <div className={`w-3 h-3 rounded-full ${health?.status === "ok" ? "bg-green-500" : "bg-red-500"}`} />
            <div>
              <div className="text-sm font-medium text-gray-900">Status: {health?.status ?? "unknown"}</div>
              <div className="text-xs text-gray-500">Mode: {health?.mode ?? "unknown"} | Version: {health?.version ?? "n/a"}</div>
            </div>
          </div>
        )}
        <button
          onClick={refreshHealth}
          className="mt-2 text-xs text-blue-600 hover:text-blue-800"
          disabled={healthLoading}
        >
          {healthLoading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {/* Key metrics */}
      {metricsError ? (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">Unable to load metrics: {metricsError}</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {metrics.length === 0 ? (
            <div className="col-span-3 text-center py-8 text-gray-500">
              No metrics available from backend.
            </div>
          ) : (
            metrics.map((m) => (
              <MetricCard key={m.name} metric={m} />
            ))
          )}
        </div>
      )}

      {/* Recent events */}
      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-2">Recent Events</h3>
        {eventsLoading ? (
          <div className="text-center py-4 text-gray-500">Loading events...</div>
        ) : events.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No events recorded.</div>
        ) : (
          <div className="max-h-64 overflow-y-auto space-y-2">
            {events.slice(0, 10).map((ev) => (
              <div key={ev.id} className="flex items-start gap-2 p-1 border-b border-gray-50 last:border-0 text-xs">
                <span className="font-mono text-gray-400">{ev.seq}</span>
                <span className="text-gray-700">{ev.kind}</span>
                <span className="ml-auto text-gray-500">{ev.timestamp}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
