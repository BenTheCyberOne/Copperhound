// Admin → Server: network conduits between zones (PUT /network), so paths
// and exposure can respect firewall rules (docs/OT.md, "Network reachability").

import { useEffect, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { NetworkConfig, NetworkStatus } from "../../api/types";
import { useApp } from "../../state/AppContext";

const EXAMPLE: NetworkConfig = {
  attacker_zone: "IT",
  conduits: [
    { from: "IT", to: "OT-DMZ", services: ["rdp"] },
    { from: "OT-DMZ", to: "OT-L2", services: ["rdp"] },
    { from: "OT-L2", to: "OT-L1", services: ["plc"] },
  ],
};

const pretty = (c: NetworkConfig | null) => JSON.stringify(c ?? EXAMPLE, null, 2);

export function NetworkPanel() {
  const { notify, track } = useApp();
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.network().then(
      (s) => {
        setStatus(s);
        setText(pretty(s.conduits));
      },
      () => setStatus({ conduits: null, zones: [], error: null }),
    );
  }, []);
  if (!status) return null;

  const save = async () => {
    let parsed: NetworkConfig;
    try {
      parsed = JSON.parse(text) as NetworkConfig;
    } catch (e) {
      setError(`Not valid JSON: ${errorMessage(e)}`);
      return;
    }
    try {
      const s = await track(api.saveNetwork(parsed));
      setStatus(s);
      setText(pretty(s.conduits));
      setError(null);
      notify("Network conduits saved.");
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  const remove = async () => {
    try {
      const s = await track(api.deleteNetwork());
      setStatus(s);
      setText(pretty(null));
      setError(null);
      notify("Network conduits removed.");
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <section className="card form-stack">
      <div className="section-head">
        <h2>Network conduits</h2>
        <span className={`tag ${status.conduits ? "ok" : "off"}`}>{status.conduits ? "configured" : "off"}</span>
      </div>
      <p className="muted small-text">
        Which services may cross between network zones. Hosts are placed in zones by their <code>net_zone</code> property
        (OpenGraph). With conduits set, the Path tab can show only paths the firewall allows. Services: smb, rdp, winrm, rpc,
        mssql, plc, ssh or *; <code>*</code> as a zone means every zone. See docs/OT.md.
      </p>
      <textarea
        className="chql-editor"
        rows={12}
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        aria-label="Network conduits (JSON)"
      />
      {(error ?? status.error) && (
        <p className="error" role="alert">
          {error ?? status.error}
        </p>
      )}
      {status.zones.length > 0 && (
        <table className="data-table compact">
          <thead>
            <tr>
              <th>Zone</th>
              <th className="num">Hosts with this net_zone</th>
            </tr>
          </thead>
          <tbody>
            {status.zones.map((z) => (
              <tr key={z.name}>
                <td>
                  {z.name}
                  {z.name.toLowerCase() === status.conduits?.attacker_zone.toLowerCase() && <span className="tag">attacker starts here</span>}
                </td>
                <td className="num">{z.hosts.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="row gap">
        <button type="button" className="primary" onClick={() => void save()}>
          Save conduits
        </button>
        {status.conduits && (
          <button type="button" onClick={() => void remove()}>
            Remove
          </button>
        )}
      </div>
    </section>
  );
}
