import { kindIcon, kindShort } from "../graph/kinds";
import { useSettings } from "../settings/SettingsContext";
import { useCatalog } from "../state/CatalogContext";

/** Kind label with its canvas colour; `dotOnly` renders just the coloured dot (kind in the tooltip). */
export function KindBadge({ kind, dotOnly }: { kind: string; dotOnly?: boolean }) {
  const { kindColor } = useSettings();
  useCatalog(); // re-render when shared kind styles load
  const style = { ["--kind" as string]: kindColor(kind) };
  if (dotOnly) return <span className="kind-dot" style={style} title={kind} aria-label={kind} role="img" />;
  return (
    <span className="kind-badge" style={style}>
      {kindIcon(kind) && <span className="kind-icon">{kindIcon(kind)} </span>}
      {kindShort(kind)}
    </span>
  );
}
