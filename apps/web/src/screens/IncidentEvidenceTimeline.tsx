/**
 * Incident Evidence Timeline - shows events from the evidence chain with
 * citations and integrity state.
 */

import React, { useEffect, useState } from "react";
import { api, EventData } from "../api";
import { LabelChip } from "../components/LabelChip";

export function IncidentEvidenceTimeline() {
  const [events, setEvents] = useState<EventData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listEvents().then(setEvents).catch((e) => setError(e instanceof Error ? e.message : "unknown error")).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Incident Evidence Timeline</h2>
        <p className="text-gray-600">
          Every event in the chain cites real event IDs. Each event is OBSERVED,
          INFERRED, SIMULATED, or VERIFIED - never mixed without a label.
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">Error: {error}</p>
        </div>
      )}

      <div className="bg-white border rounded-lg">
        {loading ? (
          <div className="text-center py-8 text-gray-500">Loading events...</div>
        ) : events.length === 0 ? (
          <div className="text-center py-8 text-gray-500">No evidence events recorded.</div>
        ) : (
          <div className="divide-y divide-gray-100">
            {events.slice(0, 50).map((ev) => (
              <div key={ev.id} className="p-3 border-b border-gray-50 last:border-0">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <LabelChip label={ev.kind} />
                    <span className="font-mono text-xs text-gray-400">#{ev.seq}</span>
                  </div>
                  <span className="text-xs text-gray-400 font-mono">{ev.timestamp}</span>
                </div>
                <div className="mt-1 text-sm text-gray-700 break-all">
                  {JSON.stringify(ev.payload).slice(0, 200)}{ev.payload && JSON.stringify(ev.payload).length > 200 ? "..." : ""}
                </div>
                <div className="mt-1 text-xs text-gray-500 font-mono">
                  event_id: {ev.id} | run: {ev.run_id ?? "none"}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
