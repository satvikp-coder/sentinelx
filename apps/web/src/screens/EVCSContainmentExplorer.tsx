/**
 * EVCS Containment Explorer - shows containment branch outcomes.
 * SIMULATED data only - never claims real containment was tested.
 */

import React, { useEffect, useState } from "react";
import { LabelChip } from "../components/LabelChip";

const MITIGATIONS = [
  { id: "BLOCK_ONLY", name: "Block Only", kind: "SIMULATED" },
  { id: "PAUSE_AND_CONFIRM", name: "Pause & Confirm", kind: "SIMULATED" },
  { id: "ROLLBACK_AND_RETRY", name: "Rollback & Retry", kind: "SIMULATED" },
  { id: "STRIP_UNTRUSTED", name: "Strip Untrusted", kind: "SIMULATED" },
  { id: "LIMIT_NAVIGATION", name: "Limit Navigation", kind: "SIMULATED" },
  { id: "TRAP", name: "Trap", kind: "SIMULATED" },
];

export function EVCSContainmentExplorer() {
  const [branches, setBranches] = useState<Array<{
    mitigation: string;
    unauthorized: number;
    completed: number;
    disruption: number;
    kind: string;
  }>>([]);

  // Branches are populated from backend if available; otherwise empty state
  useEffect(() => {
    // No backend endpoint for EVCS branches yet - show SIMULATED placeholder
    setBranches([]);
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">EVCS Containment Explorer</h2>
        <p className="text-gray-600">
          IncidentTwin containment branches (EVCS). Each branch is re-executed in
          a resettable lab fixture. All data is SIMULATED until a live backend
          provides real results.
        </p>
      </div>

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Containment Branches</h3>
        <div className="space-y-2">
          {MITIGATIONS.map((m) => (
            <div key={m.id} className="flex items-center justify-between p-2 border rounded bg-gray-50">
              <div>
                <div className="text-sm font-medium text-gray-800">{m.name}</div>
                <div className="text-xs text-gray-500">{m.id}</div>
              </div>
              <div className="flex items-center gap-3 text-xs">
                <LabelChip label={m.kind} />
                <span className="text-gray-500">No live data</span>
              </div>
            </div>
          ))}
          <div className="pt-2 text-xs text-gray-500">
            EVCS branch data is not available from the backend yet. This screen
            is a placeholder for live containment exploration.
          </div>
        </div>
      </div>

      <div className="bg-amber-50 border border-amber-100 rounded-lg p-3">
        <p className="text-sm text-amber-800">
          <strong>Limitation:</strong> EVCS results require a live backend with
          containment branch data. Currently shows SIMULATED structure only.
        </p>
      </div>
    </div>
  );
}
