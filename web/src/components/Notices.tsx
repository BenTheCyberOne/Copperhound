import { useApp } from "../state/AppContext";

export function Notices() {
  const { notices, dismiss } = useApp();
  return (
    <div className="notices" aria-live="polite">
      {notices.map((n) => (
        <div key={n.id} className={`notice ${n.kind}`} role={n.kind === "error" ? "alert" : "status"}>
          <span>{n.text}</span>
          <button type="button" className="icon-btn" aria-label="Dismiss" onClick={() => dismiss(n.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
