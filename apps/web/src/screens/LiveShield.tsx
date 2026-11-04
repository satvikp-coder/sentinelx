import React, { useEffect, useState } from "react";
import { api, ShieldRuleData } from "../api";
import { LabelChip } from "../components/LabelChip";

export function LiveShield() {
  const [evidence, setEvidence] = useState<Awaited<ReturnType<typeof api.shieldEvidence>> | null>(null);
  const [rules, setRules] = useState<ShieldRuleData[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [route, setRoute] = useState("/demo-blocked");
  const [mode, setMode] = useState("monitor");
  const [ttl, setTtl] = useState(5);
  const [session, setSession] = useState("");

  const refresh = async () => {
    const [currentRules, audit] = await Promise.all([api.listShieldRules(), api.shieldEvidence()]);
    setRules(currentRules); setEvidence(audit);
  };
  useEffect(() => {
    refresh().catch(e => setError(String(e))).finally(() => setLoading(false));
    const timer = setInterval(() => { refresh().catch(e => setError(String(e))); }, 5000);
    return () => clearInterval(timer);
  }, []);
  const perform = async (action: () => Promise<unknown>) => {
    setBusy(true); setError(null);
    try { await action(); await refresh(); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  };
  return <div className="space-y-6">
    <h2 className="text-2xl font-bold">Live Shield</h2>
    <p role="note">TEMPORARY SHIELD, NOT A FIX. Local demo operator only. ACTIVE means a
      durable rule is available to the proxy using the same runtime database and target.
      Traffic blocks only when both proxy and rule use enforce mode; verify real traffic.</p>
    {error && <p role="alert" className="text-red-700">{error}</p>}
    <form className="space-y-3 border rounded-lg p-4" onSubmit={e => {
      e.preventDefault(); void perform(() => api.createShieldRule({route_pattern: route,
        intent: "RECON", mode, ttl_minutes: ttl, reason: "Local operator proposal"}));
    }}>
      <h3>Propose a temporary rule</h3>
      <label>Route pattern <input required value={route} maxLength={200}
        onChange={e => setRoute(e.target.value)} /></label>{" "}
      <label>Mode <select aria-label="Mode" value={mode} onChange={e => setMode(e.target.value)}>
        <option value="monitor">Monitor</option><option value="recommend">Recommend</option>
        <option value="enforce">Enforce</option></select></label>{" "}
      <label>TTL (minutes) <input type="number" min={1} max={1440} required value={ttl}
        onChange={e => setTtl(Number(e.target.value))} /></label>{" "}
      <button disabled={busy} type="submit">Propose rule</button>
    </form>
    <div className="border rounded-lg p-4">
      <label>Approval session ID <input value={session} onChange={e => setSession(e.target.value)} /></label>{" "}
      <button disabled={busy} onClick={() => void perform(async () => {
        const created = await api.createSession({scenario_id: "S1", lab: "synthetic", arm: "A"});
        setSession(created.id);
      })}>Create local approval session</button>
      <p>Approve only the displayed rule you intend to enforce. The server binds approval to its
        exact content and runs a representative benign replay before activation.</p>
    </div>
    <section aria-label="Durable shield evidence" className="border rounded-lg p-4">
      <h3>Durable shield evidence</h3>
      {evidence ? <>
        <p role="status">Chain: {evidence.chain_status} | Events checked: {evidence.events_checked}</p>
        {!evidence.ok && <p role="alert">Evidence integrity verification failed. Investigate before relying on this record.</p>}
        <ul>{evidence.events.slice(-5).map(event => <li key={event.id}>
          {event.kind} | {event.state} | {event.timestamp_utc} | {event.id}
        </li>)}</ul>
      </> : <p>Evidence not yet available.</p>}
    </section>
    <section aria-label="Shield rules" className="border rounded-lg p-4">
      <h3>All shield rules</h3>
      {loading ? <p>Loadingâ€¦</p> : rules.length === 0 ? <p>No shield rules.</p> : rules.map(r =>
        <article key={r.rule_id} className="p-3 border-b">
          <strong>{r.route_pattern}</strong>{" "}<LabelChip label={r.state} />
          <p>Mode: {r.mode} | Intent: {r.intent} | TTL: {r.ttl_minutes} min</p>
          <p>Expires: {r.expires_at ?? "not recorded"}</p>
          {r.state === "PROPOSED" && <button disabled={busy || !session}
            onClick={() => void perform(async () => {
              await api.recordShieldApproval(r.rule_id, session);
              await api.approveShieldRule(r.rule_id, session);
            })}>Approve and activate {r.route_pattern}</button>}
          {["ACTIVE", "PROPOSED"].includes(r.state) && <>
            <button disabled={busy} onClick={() => void perform(() => api.expireShieldRule(r.rule_id))}>Expire</button>{" "}
            <button disabled={busy} onClick={() => void perform(() => api.removeShieldRule(r.rule_id))}>Remove</button>
          </>}
        </article>)}
    </section>
  </div>;
}
