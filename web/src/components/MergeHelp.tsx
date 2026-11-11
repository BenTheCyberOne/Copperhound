import { useEffect, useRef, useState } from "react";

/** "How merging works" button with a short explanation in a popover (Escape / outside click closes). */
export function MergeHelp({ label = "How merging works" }: { label?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <span className="help-popover-anchor" ref={ref}>
      <button type="button" className="link-btn" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        {label} <span aria-hidden="true">ⓘ</span>
      </button>
      {open && (
        <div className="help-popover" role="dialog" aria-label="How merging works">
          <ul>
            <li>
              <strong>One object, many files.</strong> Every upload (and every zip entry) is read together. Objects are matched
              by SID / objectGUID / Entra id, so domains and tenants sit side by side and repeated dumps describe the same
              nodes.
            </li>
            <li>
              <strong>Newest collection wins</strong> (policy <code>newest</code>). Name, kind and flags come from the newest
              collection that has the object. Properties merge key by key: newer values win, keys only an older collector
              wrote are kept.
            </li>
            <li>
              <strong>Relationships.</strong> Relationships listed in an object&apos;s own record (ACEs, members, sessions, local
              admins, containment, GPO links, …) come from its newest collection. Removed ACEs or memberships disappear.
              Categories the newer dump did not collect keep the older data.
            </li>
            <li>
              <strong>Undated files</strong> (and files with equal times) are merged as a plain union. Prefix a file name with{" "}
              <code>YYYYMMDDHHMMSS_</code> (UTC) to date it.
            </li>
            <li>
              <strong>Replace or merge uploads.</strong> UI uploads are always added to the current uploads, so delete old
              files to drop them. The watch folder&apos;s <em>replace</em> mode archives earlier uploads first; <em>merge</em>{" "}
              mode keeps them and the rules above apply.
            </li>
          </ul>
        </div>
      )}
    </span>
  );
}
