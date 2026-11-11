import { useState } from "react";
import { api } from "../api/client";
import { ExposureReport } from "../components/ExposureReport";
import { PathHops, hopsOf } from "../components/PathHops";
import { StatusView } from "../components/StatusView";
import { useChokeActions } from "../components/useChokeActions";
import { ZoneSelect } from "../components/ZoneSelect";
import { useAnalysis } from "../hooks/useAnalysis";
import { useApp } from "../state/AppContext";
import { useCatalog } from "../state/CatalogContext";
import { useZones } from "../state/ZonesContext";

export function Tier0Tab({ active }: { active: boolean }) {
  const { marksVersion } = useApp();
  const { generation } = useCatalog();
  const { zone: zoneById } = useZones();
  const [zone, setZone] = useState("tier0");
  const zoneName = zoneById(zone)?.name ?? "Tier Zero";
  // The report depends on marks and the loaded graph; reload when either changes.
  const report = useAnalysis(
    () => (zone === "tier0" ? api.tier0(25) : api.zoneExposure(zone, 25)),
    `${zone}|${marksVersion}|${generation}`,
    active,
  );
  const { shown, showChoke, addChoke } = useChokeActions(zone);

  return (
    <div className="tab-body">
      <div className="section-head">
        <h3>Exposure</h3>
        <button type="button" className="small" onClick={report.reload} disabled={report.loading}>
          {report.loading ? "Analysing…" : "Refresh"}
        </button>
      </div>
      <label className="inline-field">
        Zone
        <ZoneSelect value={zone} onChange={setZone} label="Exposure zone" />
      </label>
      <StatusView state={report} what={`${zoneName} exposure`} />
      {report.data && (
        <ExposureReport
          report={report.data}
          zoneName={zoneName}
          activeKey={shown?.key ?? null}
          onShowChoke={(cp) => void showChoke(cp)}
          onAddToFixList={addChoke}
        />
      )}
      {shown && <PathHops hops={hopsOf(shown.result)} nodes={shown.result.nodes} />}
    </div>
  );
}
