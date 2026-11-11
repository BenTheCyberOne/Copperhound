import { Planner } from "./Planner";
import { Simulator } from "./Simulator";

export function RemediationView() {
  return (
    <div className="view-page">
      <header className="view-head">
        <div>
          <h1>Remediation</h1>
          <p className="muted">
            Try fixes before making them: simulate removing edges, edge kinds or objects, or let the planner pick the fixes
            that cut the most attack paths.
          </p>
        </div>
      </header>
      <div className="two-pane">
        <Simulator />
        <Planner />
      </div>
    </div>
  );
}
