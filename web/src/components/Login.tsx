import { useEffect, useState, type FormEvent } from "react";
import { ApiError, api, errorMessage, isMockMode } from "../api/client";
import type { AuthProviders, Role } from "../api/types";
import { Logo } from "./Logo";

/** Friendly text for /#/login?sso_error=<code> (details are only in the audit log). */
const SSO_ERRORS: Record<string, string> = {
  disabled: "Single sign-on is not enabled on this server.",
  config: "Single sign-on is misconfigured on the server (the redirect URL could not be determined). Ask an administrator.",
  idp_unreachable: "The identity provider could not be reached. Try again later or ask an administrator.",
  state: "The sign-in attempt expired or was started in another browser. Please try again.",
  idp_error: "The identity provider did not complete the sign-in (it was cancelled or consent was denied).",
  token: "The identity provider's response could not be verified. Try again; if it keeps failing, ask an administrator.",
  denied: "Your account is not allowed to use CopperHound. Ask an administrator to add you to a group that grants access.",
  disabled_user: "Your CopperHound account is disabled. Ask an administrator.",
  conflict: "Your user name already belongs to another CopperHound account. Ask an administrator.",
  server: "The server could not store your account. Try again later.",
};

export function ssoErrorText(code: string): string {
  return SSO_ERRORS[code] ?? `Single sign-on failed (${code}).`;
}

/** ?sso_error from a #/login hash (pure: safe for StrictMode's double initialisers). */
function readSsoError(): string | null {
  const m = /^#\/login\?(.*)$/.exec(window.location.hash);
  return m ? new URLSearchParams(m[1]).get("sso_error") : null;
}

/** Where the SPA should land after SSO: the page the user was on, unless it is a sign-in route. */
function returnTo(): string | null {
  const h = window.location.hash;
  if (!h || h === "#" || h === "#/" || /^#\/(login|sso)\b/.test(h)) return null;
  return `/${h}`;
}

function ssoHref(loginUrl: string): string {
  const rt = returnTo();
  if (!rt) return loginUrl;
  return `${loginUrl}${loginUrl.includes("?") ? "&" : "?"}return_to=${encodeURIComponent(rt)}`;
}

interface Props {
  onLoggedIn: (username: string, role: Role) => void;
  notice: string | null;
  /** An SSO code from #/sso is being redeemed. */
  ssoPending?: boolean;
}

export function Login({ onLoggedIn, notice, ssoPending }: Props) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<AuthProviders | null>(null);
  const [providersFailed, setProvidersFailed] = useState(false);
  const [breakGlass, setBreakGlass] = useState(false);
  const [ssoError] = useState(readSsoError);

  // Drop ?sso_error from the URL so a reload does not repeat the message.
  useEffect(() => {
    if (/^#\/login\?/.test(window.location.hash)) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
  }, []);

  useEffect(() => {
    let live = true;
    api.authProviders().then(
      (p) => live && setProviders(p),
      // Older servers have no /auth/providers: plain password sign-in.
      () => live && setProvidersFailed(true),
    );
    return () => {
      live = false;
    };
  }, []);

  const [needOtp, setNeedOtp] = useState(false);
  const [otp, setOtp] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(username, password, needOtp ? otp.trim() : undefined);
      onLoggedIn(res.username, res.role ?? "viewer");
    } catch (err) {
      if (err instanceof ApiError && err.mfaRequired) {
        setError(needOtp ? errorMessage(err) : null);
        setNeedOtp(true);
        setOtp("");
        return;
      }
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const saml = providers?.saml?.enabled ? providers.saml : null;
  const sso = providers?.sso.enabled ? providers.sso : saml;
  const second = providers?.sso.enabled && saml ? saml : null;
  const passwordForm = providersFailed || (providers !== null && (providers.password_login || breakGlass));
  const offerBreakGlass = providers !== null && !providers.password_login && providers.admin_password_login && !breakGlass;
  const noMethod = providers !== null && !sso && !providers.password_login && !providers.admin_password_login;

  return (
    <main className="login-screen">
      <form className="login-card" onSubmit={(e) => void submit(e)}>
        <div className="login-brand">
          <Logo size={44} />
          <div>
            <h1>CopperHound</h1>
            <p className="muted small-text">Attack-path analysis for Active Directory and Azure</p>
          </div>
        </div>
        {notice && <p className="notice warn">{notice}</p>}
        {ssoError && (
          <p className="notice error" role="alert">
            <span>{ssoErrorText(ssoError)}</span>
          </p>
        )}
        {ssoPending && (
          <p className="muted" role="status">
            <span className="spinner" aria-hidden="true" /> Completing single sign-on…
          </p>
        )}
        {!providers && !providersFailed && !ssoPending && <p className="muted small-text">Loading sign-in options…</p>}
        {sso && !ssoPending && (
          <a className="button-link primary sso-button" href={ssoHref(sso.login_url)}>
            Sign in with {sso.display_name}
          </a>
        )}
        {second && !ssoPending && (
          <a className="button-link sso-button" href={ssoHref(second.login_url)}>
            Sign in with {second.display_name}
          </a>
        )}
        {sso && passwordForm && (
          <div className="login-divider" role="separator">
            <span>{breakGlass ? "administrator sign-in" : "or with a password"}</span>
          </div>
        )}
        {passwordForm && !ssoPending && (
          <>
            <label>
              Username
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus={!sso} />
            </label>
            <label>
              Password
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
            </label>
            {needOtp && (
              <label>
                Two-factor code
                <input
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  placeholder="123456 or a recovery code"
                  required
                  autoFocus
                />
              </label>
            )}
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <button type="submit" className={sso ? "" : "primary"} disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
            {breakGlass && (
              <p className="muted small-text">
                Password sign-in is reserved for the built-in <code>admin</code> account while single sign-on is in use.
              </p>
            )}
          </>
        )}
        {offerBreakGlass && (
          <button type="button" className="link-btn login-breakglass" onClick={() => setBreakGlass(true)}>
            Administrator sign-in
          </button>
        )}
        {noMethod && <p className="error">No sign-in method is enabled on this server. Ask an administrator.</p>}
        {isMockMode && (
          <p className="muted small-text">
            Mock mode: <code>admin</code> / <code>copperhound</code>, <code>analyst</code> / <code>analyst-password</code> or{" "}
            <code>viewer</code> / <code>viewer-password</code>. The SSO button signs in <code>alice@corp.example</code>.
          </p>
        )}
      </form>
    </main>
  );
}
