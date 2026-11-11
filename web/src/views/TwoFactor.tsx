// Account → two-factor sign-in (TOTP): enrol with a QR code, show the
// recovery codes once, turn it off with a current code.

import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "../api/client";
import { useApp } from "../state/AppContext";

type Status = { enabled: boolean; pending: boolean; recovery_codes_left: number };

export function TwoFactor() {
  const { notify } = useApp();
  const [status, setStatus] = useState<Status | null>(null);
  const [setup, setSetup] = useState<{ secret: string; qr_svg: string } | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api.mfaStatus().then(setStatus, (e: unknown) => setError(errorMessage(e)));
  }, []);
  useEffect(load, [load]);

  const run = async (f: () => Promise<void>) => {
    setError(null);
    try {
      await f();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  if (!status) return <p className="muted">{error ?? "Loading…"}</p>;

  if (recovery) {
    return (
      <div className="form-stack">
        <p className="notice warn">
          <span>Two-factor sign-in is on. Store these recovery codes somewhere safe; each works once and they are not shown again.</span>
        </p>
        <pre className="code-block recovery-codes">{recovery.join("\n")}</pre>
        <div className="row gap">
          <button type="button" onClick={() => void navigator.clipboard.writeText(recovery.join("\n")).catch(() => undefined)}>
            Copy
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => {
              setRecovery(null);
              load();
            }}
          >
            I have stored them
          </button>
        </div>
      </div>
    );
  }

  if (status.enabled) {
    return (
      <div className="form-stack">
        <p>
          <span className="tag ok">on</span> Sign-in asks for a code from your authenticator app.{" "}
          <span className="muted small-text">{status.recovery_codes_left} recovery codes left.</span>
        </p>
        <label className="form-field">
          <span className="field-title">Current code (or a recovery code) to turn it off</span>
          <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" />
        </label>
        <div className="row gap">
          <button
            type="button"
            disabled={!code.trim()}
            onClick={() =>
              void run(async () => {
                await api.mfaDisable(code.trim());
                setCode("");
                notify("Two-factor sign-in turned off.");
                load();
              })
            }
          >
            Turn off
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>
    );
  }

  return (
    <div className="form-stack">
      <p className="muted small-text">
        Protect password sign-in with a time-based code from an authenticator app (Microsoft or Google Authenticator, 1Password,
        Bitwarden, …). API tokens are not affected.
      </p>
      {!setup ? (
        <div className="row gap">
          <button type="button" className="primary" onClick={() => void run(async () => setSetup(await api.mfaSetup()))}>
            Set up two-factor sign-in
          </button>
        </div>
      ) : (
        <>
          <p className="small-text">Scan this code with the app, or enter the key by hand, then type the 6-digit code it shows.</p>
          {/* Rendered as an image (not inline markup), so the SVG cannot run anything. */}
          <img className="mfa-qr" alt="QR code for the authenticator app" src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qr_svg)}`} />
          <code className="break small-text">{setup.secret.replace(/(.{4})/g, "$1 ").trim()}</code>
          <label className="form-field">
            <span className="field-title">Code from the app</span>
            <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" maxLength={8} />
          </label>
          <div className="row gap">
            <button
              type="button"
              className="primary"
              disabled={code.trim().length < 6}
              onClick={() =>
                void run(async () => {
                  const r = await api.mfaEnable(code.trim());
                  setCode("");
                  setSetup(null);
                  setRecovery(r.recovery_codes);
                })
              }
            >
              Turn on
            </button>
            <button type="button" onClick={() => setSetup(null)}>
              Cancel
            </button>
          </div>
        </>
      )}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
