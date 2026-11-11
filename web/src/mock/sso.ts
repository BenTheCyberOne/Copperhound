// Mock OpenID Connect single sign-on, mirroring crates/server/src/sso.rs.
// There is no real IdP: the provider's login_url points straight back into the SPA
// with a code the mock exchange accepts, as if the IdP had signed in a demo user.

import type { ApiResponse } from "../api/client";
import type { AuthProviders, Role, SsoConfig, SsoMappedRole, SsoSettingsResponse, SsoTestResult } from "../api/types";

const CALLBACK_PATH = "/api/v1/auth/oidc/callback";

/** Prefix of the codes the mock "IdP" hands back; each code signs in the demo SSO user once. */
export const MOCK_IDP_CODE = "mock-idp";

/** The identity the mock IdP returns. */
export const MOCK_IDP_USER = { username: "alice@corp.example", email: "alice@corp.example", groups: ["CopperHound.Analyst", "All Staff"] };

let config: SsoConfig = {
  enabled: true,
  display_name: "Corp SSO",
  issuer: "https://login.example.com/corp/v2.0",
  client_id: "6c2f0d1e-copperhound-mock",
  client_secret_set: true,
  redirect_url: "",
  scopes: ["openid", "profile", "email"],
  username_claim: "preferred_username",
  groups_claim: "groups,roles",
  role_mapping: { admin: ["CopperHound.Admin"], analyst: ["CopperHound.Analyst"], viewer: [] },
  default_role: "viewer",
  allowed_email_domains: [],
  allow_password_login: true,
  disable_admin_password_login: false,
  allow_insecure_http: false,
};
/** Pretend COPPERHOUND_OIDC_GROUPS_CLAIM is set, so that field is shown as env-managed. */
const ENV_OVERRIDES: string[] = ["groups_claim"];
let ssoAdminSignedIn = false;

const ok = (body: unknown): ApiResponse => ({ status: 200, body });
const fail = (status: number, error: string): ApiResponse => ({ status, body: { error } });

const configured = () => config.enabled && !!config.issuer && !!config.client_id;

/** Whether the built-in admin may still use its password (break-glass rules). */
function adminPasswordLogin(): boolean {
  return !(configured() && !config.allow_password_login && config.disable_admin_password_login && ssoAdminSignedIn);
}

export function providers(): AuthProviders {
  return {
    password_login: !configured() || config.allow_password_login,
    admin_password_login: adminPasswordLogin(),
    sso: {
      enabled: configured(),
      type: "oidc",
      display_name: config.display_name || "Single sign-on",
      // A real server redirects to the IdP from /api/v1/auth/oidc/login; the mock skips
      // straight to the SPA callback route.
      login_url: `/#/sso?code=${MOCK_IDP_CODE}-${Math.random().toString(16).slice(2, 10)}`,
    },
  };
}

/** null when the password may be used; otherwise the 403 message (checked after a correct password). */
export function passwordRefusal(username: string): string | null {
  const refused = username === "admin" ? !adminPasswordLogin() : configured() && !config.allow_password_login;
  return refused ? "password sign-in is disabled for this account; use single sign-on" : null;
}

/** Role for the mock IdP identity, or null when it maps to no role (default_role deny). */
export function mappedRole(groups: string[]): Role | null {
  const has = (r: SsoMappedRole) => config.role_mapping[r].some((v) => groups.some((g) => g.toLowerCase() === v.toLowerCase()));
  if (has("admin")) return "admin";
  if (has("analyst")) return "analyst";
  if (has("viewer")) return "viewer";
  return config.default_role === "deny" ? null : config.default_role;
}

export function ssoEnabled(): boolean {
  return configured();
}

export function noteSsoAdminSignIn(): void {
  ssoAdminSignedIn = true;
}

function settingsResponse(): SsoSettingsResponse {
  return {
    config: { ...config, client_secret: undefined },
    env_overrides: ENV_OVERRIDES,
    redirect_url_effective: config.redirect_url || `${window.location.origin}${CALLBACK_PATH}`,
    callback_path: CALLBACK_PATH,
    sso_admin_signed_in: ssoAdminSignedIn,
    admin_password_login: adminPasswordLogin(),
    break_glass_env: false,
  };
}

const isHttps = (u: string) => /^https:\/\/[^/\s]+/i.test(u);
const isLoopbackHttp = (u: string) => /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(u);

export function getSsoSettings(): ApiResponse {
  return ok(settingsResponse());
}

export function putSsoSettings(body: Partial<SsoConfig>): ApiResponse {
  const next: SsoConfig = {
    enabled: body.enabled ?? false,
    display_name: body.display_name ?? "Single sign-on",
    issuer: (body.issuer ?? "").trim(),
    client_id: (body.client_id ?? "").trim(),
    client_secret_set: config.client_secret_set,
    redirect_url: (body.redirect_url ?? "").trim(),
    scopes: body.scopes?.length ? body.scopes : ["openid", "profile", "email"],
    username_claim: body.username_claim || "preferred_username",
    groups_claim: body.groups_claim || "groups",
    role_mapping: { admin: [], analyst: [], viewer: [], ...body.role_mapping },
    default_role: body.default_role ?? "deny",
    allowed_email_domains: body.allowed_email_domains ?? [],
    allow_password_login: body.allow_password_login ?? true,
    disable_admin_password_login: body.disable_admin_password_login ?? false,
    allow_insecure_http: body.allow_insecure_http ?? false,
  };
  if (next.display_name.length > 64) return fail(400, "display_name must be at most 64 characters");
  if (next.enabled && !next.issuer) return fail(400, "issuer is required when SSO is enabled");
  if (next.enabled && !next.client_id) return fail(400, "client_id is required when SSO is enabled");
  if (next.issuer && !isHttps(next.issuer) && !isLoopbackHttp(next.issuer) && !(next.allow_insecure_http && /^http:\/\//i.test(next.issuer))) {
    return fail(400, "issuer must be an https:// URL (http:// only for loopback or with allow_insecure_http)");
  }
  if (next.redirect_url && !next.redirect_url.replace(/\/$/, "").endsWith(CALLBACK_PATH)) {
    return fail(400, `redirect_url must end with ${CALLBACK_PATH}`);
  }
  if ((next.default_role as string) === "admin") return fail(400, "default_role must be viewer, analyst or deny");
  if (next.disable_admin_password_login) {
    if (!next.enabled || next.allow_password_login) {
      return fail(400, "disable_admin_password_login requires enabled SSO and allow_password_login: false");
    }
    if (!ssoAdminSignedIn) {
      return fail(400, "disable_admin_password_login is only accepted after an SSO account with the admin role has signed in");
    }
  }
  if (typeof body.client_secret === "string") next.client_secret_set = body.client_secret !== "";
  // Environment variables win over the stored value.
  if (ENV_OVERRIDES.includes("groups_claim")) next.groups_claim = config.groups_claim;
  config = next;
  return ok(settingsResponse());
}

export function testSso(body: { issuer?: string; allow_insecure_http?: boolean }): ApiResponse {
  const issuer = (body.issuer ?? config.issuer).trim().replace(/\/$/, "");
  const insecure = body.allow_insecure_http ?? config.allow_insecure_http;
  let result: SsoTestResult;
  if (!issuer) result = { ok: false, error: "no issuer configured" };
  else if (!isHttps(issuer) && !isLoopbackHttp(issuer) && !insecure) {
    result = { ok: false, error: "issuer must use https:// (or enable allow_insecure_http)" };
  } else if (/unreachable|invalid/i.test(issuer)) {
    result = { ok: false, error: `could not fetch ${issuer}/.well-known/openid-configuration: connection refused` };
  } else {
    result = {
      ok: true,
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/keys`,
      userinfo_endpoint: `${issuer}/userinfo`,
      end_session_endpoint: `${issuer}/logout`,
      scopes_supported: ["openid", "profile", "email", "offline_access"],
      jwks_keys: 2,
      warnings: issuer.startsWith("http://") ? ["issuer uses plain http; tokens can be intercepted"] : [],
    };
  }
  return ok(result);
}
