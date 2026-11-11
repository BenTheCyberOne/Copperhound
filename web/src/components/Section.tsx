import type { ReactNode } from "react";

interface Props {
  title: ReactNode;
  open: boolean;
  onToggle: () => void;
  actions?: ReactNode;
  children: ReactNode;
}

/** Collapsible section with a heading button (state owned by the caller, e.g. useCollapsed). */
export function Section({ title, open, onToggle, actions, children }: Props) {
  return (
    <section className={`collapsible ${open ? "open" : ""}`}>
      <div className="collapsible-head">
        <button type="button" className="collapsible-toggle" aria-expanded={open} onClick={onToggle}>
          <span className="chevron" aria-hidden="true">
            {open ? "▾" : "▸"}
          </span>
          {title}
        </button>
        {actions}
      </div>
      {open && <div className="collapsible-body">{children}</div>}
    </section>
  );
}
