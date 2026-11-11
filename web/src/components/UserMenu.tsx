import { useEffect, useRef, useState } from "react";
import { routeHref } from "../hooks/useRoute";
import { RoleBadge, useSession } from "../state/SessionContext";

/** Header user button: name + role badge, opening Account / Sign out. */
export function UserMenu({ onLogout }: { onLogout: () => void }) {
  const { username, role } = useSession();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open]);

  return (
    <div
      className="user-menu"
      ref={ref}
      onKeyDown={(e) => {
        if (e.key === "Escape") setOpen(false);
      }}
    >
      <button type="button" className="user-button" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <span className="user">{username}</span>
        <RoleBadge role={role} />
        <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="user-dropdown" role="menu">
          <a role="menuitem" href={routeHref("account")} onClick={() => setOpen(false)}>
            Account &amp; API tokens
          </a>
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
