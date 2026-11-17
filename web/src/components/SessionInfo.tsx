// When and how a HasSession edge was seen (GET /edges/session), shown in the
// edge details. Older graphs and edges without a record show nothing.

import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { EdgeSession, NodeId } from "../api/types";

const LOGON_TYPES: Record<number, string> = {
  2: "interactive",
  4: "batch",
  5: "service",
  7: "unlock",
  8: "network cleartext",
  9: "new credentials",
  10: "remote interactive (RDP)",
  11: "cached interactive",
  12: "cached remote interactive",
  13: "cached unlock",
};

const SOURCES: Record<string, string> = {
  sessions: "SharpHound sessions",
  "privileged-sessions": "SharpHound privileged sessions",
  "registry-sessions": "SharpHound registry sessions",
  "logon-events": "logon events (4624)",
  defender: "Defender XDR",
};

function age(iso: string): string {
  const days = Math.floor((Date.now() - Date.parse(iso)) / 86_400_000);
  if (!Number.isFinite(days) || days < 0) return "";
  if (days === 0) return "today";
  if (days === 1) return "1 day ago";
  return `${days} days ago`;
}

export function SessionInfo({ src, dst }: { src: NodeId; dst: NodeId }) {
  const [s, setS] = useState<EdgeSession | null>(null);
  useEffect(() => {
    let live = true;
    api
      .edgeSession(src, dst)
      .then((r) => live && setS(r))
      .catch(() => live && setS(null));
    return () => {
      live = false;
    };
  }, [src, dst]);
  if (!s) return null;
  const types = s.logon_types.map((t) => LOGON_TYPES[t] ?? `type ${t}`);
  return (
    <dl className="session-info small-text">
      <dt>Last seen</dt>
      <dd>{s.last_seen ? `${s.last_seen.slice(0, 10)} (${age(s.last_seen)})` : "unknown (collection time not recorded)"}</dd>
      {s.first_seen && s.first_seen !== s.last_seen && (
        <>
          <dt>First seen</dt>
          <dd>{s.first_seen.slice(0, 10)}</dd>
        </>
      )}
      <dt>Seen by</dt>
      <dd>{s.sources.map((x) => SOURCES[x] ?? x).join(", ")}</dd>
      {types.length > 0 && (
        <>
          <dt>Logon types</dt>
          <dd>{types.join(", ")}</dd>
        </>
      )}
    </dl>
  );
}
