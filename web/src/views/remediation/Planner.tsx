import { useMemo, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { GraphResult, PlanResponse, PlanStep } from "../../api/types";
import { TimeChart } from "../../components/charts/TimeChart";
import { CategoryChecklist } from "../../components/CategoryChecklist";
import { KindBadge } from "../../components/KindBadge";
import { NumberField } from "../../components/NumberField";
import { ZoneSelect } from "../../components/ZoneSelect";
import { navigate } from "../../hooks/useRoute";
import { useSettings } from "../../settings/SettingsContext";
import { useApp } from "../../state/AppContext";
import { useCatalog } from "../../state/CatalogContext";
import { HandOffDialog } from "../../components/HandOffDialog";
import { useFixList } from "../../state/FixListContext";
import { useZones } from "../../state/ZonesContext";
import { downloadCsv } from "../../util/csv";
import { pctText } from "../../util/format";

const fmt = new Intl.NumberFormat();

function stepsGraph(steps: PlanStep[]): GraphResult {
  const nodes = new Map(steps.flatMap((s) => [s.node, ...s.edges.flatMap((e) => [e.src, e.dst])]).map((n) => [n.id, n]));
  const edges = steps.flatMap((s) => s.edges.map((e) => ({ src: e.src.id, dst: e.dst.id, kind: e.kind })));
  return { nodes: [...nodes.values()], edges, truncated: false, elapsed_ms: 0 };
}

export function Planner() {
  const { edgeKinds } = useCatalog();
  const { settings } = useSettings();
  const { track, loadResult, notify } = useApp();
  const fix = useFixList();
  const { zones } = useZones();
  const [scope, setScope] = useState<"zone" | "weighted">("zone");
  /** Weights changed for this plan only, by zone id. */
  const [weights, setWeights] = useState<Record<string, number>>({});
  const [zone, setZone] = useState("tier0");
  const [steps, setSteps] = useState(10);
  const [fixed, setFixed] = useState<Set<string>>(new Set(["Contains"]));
  const [protect, setProtect] = useState(true);
  const [respectCost, setRespectCost] = useState(true);
  const [liveFirst, setLiveFirst] = useState(false);
  const [plan, setPlan] = useState<PlanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [handOff, setHandOff] = useState<{ steps: PlanStep[]; title: string } | null>(null);

  const kindItems = useMemo(
    () => edgeKinds.filter((k) => k.traversable).map((k) => ({ name: k.name, category: k.category, count: k.count })),
    [edgeKinds],
  );

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      setPlan(
        await track(
          api.remediationPlan({
            ...(scope === "weighted" ? { weighted: true, weights } : { zone }),
            steps,
            fixed_kinds: [...fixed],
            protect_target_membership: protect,
            respect_fix_cost: respectCost,
            live_first: respectCost && liveFirst,
            ...(settings.queryTimeoutMs > 0 ? { timeout_ms: settings.queryTimeoutMs } : {}),
          }),
        ),
      );
    } catch (e) {
      setPlan(null);
      setError(errorMessage(e));
    } finally {
      setRunning(false);
    }
  };

  const show = (s: PlanStep[]) => {
    loadResult(stepsGraph(s), { path: false });
    navigate("explore");
  };
  const addToFix = (s: PlanStep[]) => {
    const n = fix.addEdges(s.flatMap((st) => st.edges));
    notify(n > 0 ? `Added ${n} edge${n === 1 ? "" : "s"} to the fix list.` : "Those edges are already in the fix list.");
  };
  const zoneName = (id: string) => plan?.zones?.find((z) => z.id === id)?.name ?? id;
  const perZone = (s: PlanStep) =>
    (s.zones ?? [])
      .filter((z) => z.principals_cut > 0)
      .map((z) => `${zoneName(z.id)} −${fmt.format(z.principals_cut)}`)
      .join(" · ");
  const exportCsv = (p: PlanResponse) =>
    downloadCsv(
      p.weighted ? "remediation-plan-weighted.csv" : `remediation-plan-${zone}.csv`,
      [
        "step",
        "choke_object",
        "choke_kind",
        ...(p.weighted ? ["weighted_cut", "weighted_exposure_after", "principals_cut_per_zone"] : ["principals_cut", "exposed_after"]),
        "cumulative_reduction_percent",
        "needs_window",
        "source",
        "edge",
        "target",
      ],
      p.steps.flatMap((s, i) =>
        s.edges.map((e) => [
          i + 1,
          s.node.name,
          s.node.kind,
          ...(p.weighted
            ? [s.score ?? 0, s.score_after ?? 0, (s.zones ?? []).map((z) => `${zoneName(z.id)}: ${z.principals_cut}`).join("; ")]
            : [s.principals_cut, s.exposed_after]),
          s.cumulative_reduction_percent,
          s.needs_window ? "yes" : "no",
          e.src.name,
          e.kind,
          e.dst.name,
        ]),
      ),
    );

  const last = plan?.steps[plan.steps.length - 1];
  const unit = plan?.weighted ? "weighted exposure" : "exposed principals";

  return (
    <section className="card pane" aria-labelledby="plan-title">
      <h2 id="plan-title">Remediation planner</h2>
      <p className="muted small-text">
        Each step finds the object whose onward attack edges, once removed, cut the most principals off the zone entirely.
        Cuts are exact, and the plan is recomputed after every step. Across all zones, each principal cut off a zone counts
        that zone&apos;s weight.
      </p>
      <div className="form-grid">
        <label htmlFor="plan-scope">Plan for</label>
        <select id="plan-scope" value={scope} onChange={(e) => setScope(e.target.value as "zone" | "weighted")}>
          <option value="zone">One zone</option>
          <option value="weighted">All zones, by weight</option>
        </select>
        {scope === "zone" && (
          <>
            <label htmlFor="plan-zone">Zone</label>
            <ZoneSelect id="plan-zone" value={zone} onChange={setZone} />
          </>
        )}
        <label htmlFor="plan-steps">Steps</label>
        <NumberField id="plan-steps" min={1} max={50} value={steps} onCommit={(v) => setSteps(Math.round(v))} />
      </div>
      {scope === "weighted" && (
        <table className="data-table compact">
          <caption className="muted small-text">
            Weights for this plan (0 leaves a zone out). Set the defaults on each zone&apos;s page.
          </caption>
          <thead>
            <tr>
              <th>Zone</th>
              <th className="num">Members</th>
              <th className="num">Weight</th>
            </tr>
          </thead>
          <tbody>
            {zones.map((z) => (
              <tr key={z.id}>
                <td>
                  <span className="zone-swatch" style={{ background: z.color }} /> {z.name}
                </td>
                <td className="num">{fmt.format(z.member_count)}</td>
                <td className="num">
                  <NumberField
                    aria-label={`Weight of ${z.name}`}
                    min={0}
                    max={100}
                    value={weights[z.id] ?? z.weight}
                    onCommit={(v) => setWeights((w) => ({ ...w, [z.id]: Math.round(v) }))}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <label className="toggle">
        <input type="checkbox" checked={protect} onChange={(e) => setProtect(e.target.checked)} />
        Treat members of zone groups as part of the zone (never propose removing admins from admin groups)
      </label>
      <label className="toggle" title="Node property fix_cost: 'fixed' objects are never changed, 'window' objects need a maintenance window">
        <input type="checkbox" checked={respectCost} onChange={(e) => setRespectCost(e.target.checked)} />
        Honour fix costs (skip objects marked <code>fixed</code>, flag <code>window</code>)
      </label>
      <label className="toggle">
        <input type="checkbox" checked={liveFirst} disabled={!respectCost} onChange={(e) => setLiveFirst(e.target.checked)} />
        Fixes that need no maintenance window first
      </label>
      <details className="kind-filter">
        <summary>
          Never propose these edge kinds {fixed.size > 0 && <span className="tag">{fixed.size}</span>}
        </summary>
        <CategoryChecklist label="Fixed edge kinds" items={kindItems} checked={fixed} onChange={setFixed} filterable open={false} />
      </details>
      <div className="row gap">
        <button type="button" className="primary" onClick={() => void run()} disabled={running}>
          {running ? "Planning…" : "Build plan"}
        </button>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {plan && plan.steps.length === 0 && (
        <p className="muted">Nothing to cut: no principal has a path into {plan.weighted ? "any weighted zone" : "this zone"}.</p>
      )}
      {plan && last && (
        <div className="plan-result" aria-live="polite">
          <div className="sim-cards">
            <div className="stat">
              <span className="stat-label">Baseline</span>
              <span className="stat-value">{fmt.format(plan.baseline)}</span>
              <span className="stat-label">{unit}</span>
            </div>
            <div className="stat">
              <span className="stat-label">After {plan.steps.length} steps</span>
              <span className="stat-value">{fmt.format(plan.weighted ? (last.score_after ?? 0) : last.exposed_after)}</span>
              <span className="stat-label">{unit}</span>
            </div>
            <div className="stat reduction good">
              <span className="stat-label">Reduction</span>
              <span className="stat-value">{pctText(last.cumulative_reduction_percent)}</span>
              <span className="stat-label">{plan.elapsed_ms.toFixed(0)} ms</span>
            </div>
          </div>
          {plan.truncated && <p className="warn-text small-text">The planner stopped early (time limit); the plan is partial.</p>}
          {plan.weighted && plan.zones && (
            <p className="muted small-text">
              {plan.zones.map((z) => `${z.name} ×${z.weight}: ${fmt.format(z.baseline)} exposed`).join(" · ")}
              {(plan.excluded_zones?.length ?? 0) > 0 && ` · left out (weight 0): ${plan.excluded_zones!.length}`}
            </p>
          )}

          <TimeChart
            title="Cumulative exposure reduction"
            mode="area"
            yMax={100}
            formatY={(v) => `${Math.round(v)}%`}
            xLabels={["Start", ...plan.steps.map((_, i) => `Step ${i + 1}`)]}
            series={[
              {
                key: "reduction",
                label: "Reduction",
                color: "var(--accent-strong)",
                values: [0, ...plan.steps.map((s) => s.cumulative_reduction_percent)],
              },
            ]}
          />

          <div className="row gap wrap">
            <button type="button" onClick={() => show(plan.steps)}>
              Show step edges on canvas
            </button>
            <button type="button" onClick={() => addToFix(plan.steps)}>
              Add all to fix list
            </button>
            <button type="button" onClick={() => exportCsv(plan)}>
              Export CSV
            </button>
            <button type="button" onClick={() => setHandOff({ steps: plan.steps, title: `Remediation plan: ${plan.steps.length} steps` })}>
              Hand off…
            </button>
          </div>

          <ol className="plan-steps">
            {plan.steps.map((s, i) => (
              <li key={`${s.node.id}-${i}`} className="plan-step">
                <div className="plan-step-head">
                  <span className="plan-step-no">{i + 1}</span>
                  <div className="plan-step-main">
                    <div>
                      Remove {s.edge_count === 1 ? "this edge" : `these ${s.edge_count} edges`} from{" "}
                      <KindBadge kind={s.node.kind} /> <strong>{s.node.name}</strong>
                      {s.needs_window && (
                        <>
                          {" "}
                          <span className="tag" title="An object in this step has fix_cost 'window'">
                            maintenance window
                          </span>
                        </>
                      )}
                    </div>
                    {plan.weighted ? (
                      <div className="muted small-text">
                        weighted cut {fmt.format(s.score ?? 0)} ({perZone(s)}) · {fmt.format(s.score_after ?? 0)} left ·{" "}
                        <strong>{pctText(s.cumulative_reduction_percent)}</strong> total reduction
                      </div>
                    ) : (
                      <div className="muted small-text">
                        cuts {fmt.format(s.principals_cut)} principals · {fmt.format(s.exposed_after)} still exposed ·{" "}
                        <strong>{pctText(s.cumulative_reduction_percent)}</strong> total reduction
                      </div>
                    )}
                  </div>
                  <div className="row-actions">
                    <button type="button" className="small" onClick={() => show([s])}>
                      Show
                    </button>
                    <button type="button" className="small" onClick={() => addToFix([s])}>
                      Add to fix list
                    </button>
                    <button type="button" className="small" onClick={() => setHandOff({ steps: [s], title: `Remediation step ${i + 1}: ${s.node.name}` })}>
                      Hand off…
                    </button>
                  </div>
                </div>
                <ul className="plan-edges">
                  {s.edges.map((e) => (
                    <li key={`${e.src.id}|${e.kind}|${e.dst.id}`}>
                      <span className="edge-kind">{e.kind}</span> → <KindBadge kind={e.dst.kind} dotOnly /> {e.dst.name}
                    </li>
                  ))}
                  {s.edge_count > s.edges.length && <li className="muted">… and {s.edge_count - s.edges.length} more</li>}
                </ul>
              </li>
            ))}
          </ol>
        </div>
      )}
      {handOff && <HandOffDialog
          edges={handOff.steps.flatMap((s) => s.edges)}
          more={handOff.steps.reduce((n, s) => n + Math.max(0, s.edge_count - s.edges.length), 0)}
          title={handOff.title} onClose={() => setHandOff(null)} />}
    </section>
  );
}
