// Admin → Server: shared node kind colours and icons (PUT /kind-styles), so
// custom (OpenGraph) kinds look the same for everyone.

import { useEffect, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { KindStyle } from "../../api/types";
import { kindColor } from "../../graph/kinds";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";

export function KindStylesPanel() {
  const { notify, track } = useApp();
  const { nodeKinds, reloadKindStyles } = useCatalog();
  const [styles, setStyles] = useState<Record<string, KindStyle> | null>(null);
  const [saved, setSaved] = useState<string>("{}");
  useEffect(() => {
    api.kindStyles().then(
      (m) => {
        setStyles(m);
        setSaved(JSON.stringify(m));
      },
      () => setStyles({}),
    );
  }, []);
  if (!styles) return null;
  const present = nodeKinds.filter((k) => k.count > 0).map((k) => k.name);
  const kinds = [...new Set([...present, ...Object.keys(styles)])].sort((a, b) => {
    const ca = nodeKinds.find((k) => k.name === a)?.category === "Custom" ? 0 : 1;
    const cb = nodeKinds.find((k) => k.name === b)?.category === "Custom" ? 0 : 1;
    return ca - cb || a.localeCompare(b);
  });
  const set = (k: string, patch: Partial<KindStyle>) => setStyles((s) => ({ ...(s ?? {}), [k]: { ...(s?.[k] ?? {}), ...patch } }));
  const dirty = JSON.stringify(styles) !== saved;
  const save = async () => {
    try {
      const clean: Record<string, KindStyle> = {};
      for (const [k, v] of Object.entries(styles)) {
        const s: KindStyle = {};
        if (v.color) s.color = v.color;
        if (v.icon?.trim()) s.icon = v.icon.trim();
        if (v.icon_name) s.icon_name = v.icon_name;
        if (s.color || s.icon) clean[k] = s;
      }
      const r = await track(api.saveKindStyles(clean));
      setStyles(r);
      setSaved(JSON.stringify(r));
      reloadKindStyles();
      notify("Kind styles saved for everyone.");
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };
  return (
    <section className="card form-stack">
      <h2>Node kind styles</h2>
      <p className="muted small-text">
        Default colour and icon of each node kind for all users (custom OpenGraph kinds first). A user's own colour choice in
        Settings still wins in their browser. BloodHound's <code>/api/v2/custom-nodes</code> sets the same colours.
      </p>
      <div className="kind-style-grid">
        {kinds.map((k) => (
          <div key={k} className="kind-style-row">
            <input type="color" value={styles[k]?.color ?? kindColor(k)} onChange={(e) => set(k, { color: e.target.value })} aria-label={`${k} colour`} />
            <input
              className="kind-style-icon"
              value={styles[k]?.icon ?? ""}
              maxLength={4}
              placeholder="icon"
              onChange={(e) => set(k, { icon: e.target.value })}
              aria-label={`${k} icon`}
            />
            <span className="ellipsis">{k}</span>
            {(styles[k]?.color || styles[k]?.icon) && (
              <button
                type="button"
                className="link-btn small-text"
                onClick={() =>
                  setStyles((s) => {
                    const n = { ...(s ?? {}) };
                    delete n[k];
                    return n;
                  })
                }
              >
                reset
              </button>
            )}
          </div>
        ))}
      </div>
      <div className="row gap">
        <button type="button" className="primary" disabled={!dirty} onClick={() => void save()}>
          Save styles
        </button>
      </div>
    </section>
  );
}
