// Accept a finding as a risk (reason, optional expiry) or revoke the acceptance.

import { useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { RiskAcceptance } from "../../api/types";
import { useApp } from "../../state/AppContext";
import { useSession } from "../../state/SessionContext";

export function RiskAcceptanceCard({ id, accepted, onChange }: { id: string; accepted: RiskAcceptance | null | undefined; onChange: () => void }) {
  const { notify, track } = useApp();
  const gate = useSession().gate("analyst");
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("90");
  const [error, setError] = useState<string | null>(null);

  const accept = async () => {
    setError(null);
    try {
      const d = Number(days);
      await track(api.acceptFinding(id, reason.trim(), Number.isFinite(d) && d > 0 ? Math.round(d) : undefined));
      notify("Finding accepted as a risk.");
      setReason("");
      onChange();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const revoke = async () => {
    setError(null);
    try {
      await track(api.revokeAcceptance(id));
      notify("Risk acceptance revoked; the finding is open again.");
      onChange();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <section className="card form-stack risk-card">
      <h2>Risk acceptance</h2>
      {accepted ? (
        <>
          <p>
            <span className="tag off">accepted risk</span> by <strong>{accepted.accepted_by}</strong> on {accepted.accepted_at.slice(0, 10)}
            {accepted.expires_at ? `, until ${accepted.expires_at.slice(0, 10)}` : ", no expiry"}.
          </p>
          <blockquote className="risk-reason">{accepted.reason}</blockquote>
          <p className="muted small-text">Accepted findings are left out of severity counts, new-finding alerts and the report's open findings.</p>
          <div className="row gap">
            <button type="button" onClick={() => void revoke()} {...gate}>
              Revoke acceptance
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="muted small-text">
            Accept this finding when it is a known, tolerated risk (e.g. a compensating control). It stays visible but no longer
            counts as open.
          </p>
          <label className="form-field">
            <span className="field-title">Reason</span>
            <textarea rows={2} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this risk accepted?" />
          </label>
          <label className="form-field">
            <span className="field-title">Expires after (days, empty = never)</span>
            <input type="number" min={1} max={3650} value={days} onChange={(e) => setDays(e.target.value)} />
          </label>
          <div className="row gap">
            <button type="button" onClick={() => void accept()} disabled={gate.disabled || !reason.trim()} title={gate.title}>
              Accept risk
            </button>
          </div>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
