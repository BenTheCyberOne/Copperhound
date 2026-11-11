// The signed-in user (/me) and role checks used for gating UI actions.
// The server enforces roles regardless; gating only keeps the UI honest.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Me, Role } from "../api/types";

const RANK: Record<Role, number> = { uploader: -1, viewer: 0, analyst: 1, admin: 2 };

export const ROLE_LABEL: Record<Role, string> = { uploader: "Upload-only", viewer: "Viewer", analyst: "Analyst", admin: "Admin" };

interface SessionState {
  username: string;
  role: Role;
  me: Me | null;
  reloadMe: () => void;
  atLeast: (r: Role) => boolean;
  /** Props for a control that needs role `r`: disabled with an explanatory tooltip when too low. */
  gate: (r: Role, title?: string) => { disabled: boolean; title: string | undefined };
}

const Ctx = createContext<SessionState | null>(null);

export function SessionProvider({ username, role: loginRole, children }: { username: string; role: Role; children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    api.me().then(setMe, () => undefined);
  }, [nonce]);

  // /me is authoritative (an admin may have changed the role since sign-in).
  const role = me?.role ?? loginRole;
  const reloadMe = useCallback(() => setNonce((n) => n + 1), []);
  const value = useMemo<SessionState>(() => {
    const atLeast = (r: Role) => RANK[role] >= RANK[r];
    return {
      username: me?.username ?? username,
      role,
      me,
      reloadMe,
      atLeast,
      gate: (r, title) =>
        atLeast(r)
          ? { disabled: false, title }
          : { disabled: true, title: `Requires the ${ROLE_LABEL[r].toLowerCase()} role (you are ${ROLE_LABEL[role].toLowerCase()})` },
    };
  }, [me, role, username, reloadMe]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession must be used inside SessionProvider");
  return v;
}

export function RoleBadge({ role }: { role: Role }) {
  return <span className={`role-badge role-${role}`}>{ROLE_LABEL[role]}</span>;
}

/** Inline note for pages whose changes need a higher role than the user has. */
export function ReadOnlyNote({ need, what }: { need: Role; what: string }) {
  const { atLeast, role } = useSession();
  if (atLeast(need)) return null;
  return (
    <p className="readonly-note" role="note">
      <span aria-hidden="true">🔒</span> Read-only: {what} needs the {ROLE_LABEL[need].toLowerCase()} role. You are signed in as{" "}
      {ROLE_LABEL[role].toLowerCase()}.
    </p>
  );
}
