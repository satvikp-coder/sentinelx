/**
 * Site Guard Scanner - scan targets and view scan findings.
 * Targets are limited to localhost / *.lab.test only.
 */

import React, { useState, useEffect } from "react";
import { api } from "../api";
import { LabelChip } from "../components/LabelChip";

export function SiteGuardScanner() {
  const [targets, setTargets] = useState<Array<{ target_id: string; url: string; lab: boolean; owned: boolean }>>([]);
  const [newTarget, setNewTarget] = useState({ target_id: "", url: "", lab: true });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    api.listTargets().then(setTargets).catch((e) => setError(e instanceof Error ? e.message : "unknown error"));
  }, []);

  async function addTarget(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await api.addTarget(newTarget);
      setSuccess(`Target ${newTarget.target_id} added`);
      setNewTarget({ target_id: "", url: "", lab: true });
      const updated = await api.listTargets();
      setTargets(updated);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Site Guard Scanner</h2>
        <p className="text-gray-600">
          Register lab targets for scanning. Only localhost / 127.0.0.1 / *.lab.test
          targets are allowed - no public targets.
        </p>
      </div>

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Register Target</h3>
        <form onSubmit={addTarget} className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="text"
              placeholder="target_id"
              value={newTarget.target_id}
              onChange={(e) => setNewTarget({ ...newTarget, target_id: e.target.value })}
              className="border rounded px-3 py-2 text-sm"
              required
            />
            <input
              type="text"
              placeholder="http://127.0.0.1:8080/"
              value={newTarget.url}
              onChange={(e) => setNewTarget({ ...newTarget, url: e.target.value })}
              className="border rounded px-3 py-2 text-sm"
              required
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-blue-600 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
            >
              Add Target
            </button>
          </div>
          <div className="text-xs text-gray-500">
            Only localhost (127.0.0.1, localhost) and *.lab.test URLs are accepted.
            Public URLs are rejected by the backend.
          </div>
        </form>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-100 rounded-lg p-3">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      )}
      {success && (
        <div className="bg-green-50 border border-green-100 rounded-lg p-3">
          <p className="text-sm text-green-700">{success}</p>
        </div>
      )}

      <div className="bg-white border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 mb-3">Registered Targets</h3>
        {loading ? (
          <div className="text-center py-4 text-gray-500">Loading...</div>
        ) : targets.length === 0 ? (
          <div className="text-center py-4 text-gray-500">No targets registered.</div>
        ) : (
          <div className="divide-y divide-gray-100">
            {targets.map((t) => (
              <div key={t.target_id} className="flex items-center justify-between p-2 border-b border-gray-50 last:border-0">
                <div>
                  <div className="text-sm font-medium text-gray-800">{t.target_id}</div>
                  <div className="text-xs text-gray-500 font-mono">{t.url}</div>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <LabelChip label={t.lab ? "LAB" : "PRODUCTION"} />
                  <LabelChip label={t.owned ? "OWNED" : "UNVERIFIED"} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
