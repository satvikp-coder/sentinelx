/**
 * Escalation Inbox - shows escalation tickets awaiting human review.
 */

import React, { useEffect, useState } from "react";
import { api } from "../api";
import { LabelChip } from "../components/LabelChip";

interface EscalationTicket {
  ticket_id: string;
  finding_id: string;
  state: string;
  reason: string;
  created_at: string;
}

export function EscalationInbox() {
  const [tickets, setTickets] = useState<EscalationTicket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listEscalations?.().then(setTickets).catch((e) => setError(e instanceof Error ? e.message : "unknown error")).finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Escalation Inbox</h2>
        <p className="text-gray-600">
          Escalation tickets for findings that require human review or that
          failed automatic verification.
        </p>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Escalation Tickets</h3>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading...</div>
        ) : tickets.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No escalation tickets.</div>
        ) : (
          <div className="divide-y divide-gray-100">
            {tickets.map((t) => (
              <div key={t.ticket_id} className="p-3 border-b border-gray-50 last:border-0">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="text-sm font-medium text-gray-800">{t.ticket_id}</div>
                    <div className="text-xs text-gray-500">Finding: {t.finding_id}</div>
                    <div className="text-xs text-gray-700">{t.reason}</div>
                  </div>
                  <div className="flex items-center gap-2 text-xs">
                    <LabelChip label={t.state.toUpperCase()} />
                  </div>
                </div>
                <div className="mt-1 text-xs text-gray-500 font-mono">{t.created_at}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
