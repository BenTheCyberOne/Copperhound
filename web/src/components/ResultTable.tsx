import type { ReactNode } from "react";
import type { TableData } from "../state/AppContext";
import { cellText as cell, downloadCsv } from "../util/csv";
import { asDate, TIME_KEY } from "./propertyGroups";

export function ResultTable({ table, tabs, onClose }: { table: TableData; tabs?: ReactNode; onClose: () => void }) {
  return (
    <section className="result-panel" aria-label="Tabular query result">
      <div className="result-head">
        {tabs ?? (
          <strong className="ellipsis" title={table.title}>
            {table.title}
          </strong>
        )}
        <span className="muted">
          {table.rows.length} row{table.rows.length === 1 ? "" : "s"}
          {table.truncated ? " (truncated)" : ""}
        </span>
        <span className="spacer" />
        <button type="button" className="small" onClick={() => downloadCsv("copperhound-query.csv", table.columns, table.rows)}>
          Export CSV
        </button>
        <button type="button" className="icon-btn" aria-label="Close query result" onClick={onClose}>
          ×
        </button>
      </div>
      <div className="result-scroll">
        <table className="data-table">
          <thead>
            <tr>
              {table.columns.map((c) => (
                <th key={c}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {table.rows.map((r, i) => (
              <tr key={i}>
                {r.map((v, j) => {
                  // Timestamp columns (e.g. u.lastlogontimestamp) are shown as dates; CSV keeps raw values.
                  const date = TIME_KEY.test(table.columns[j] ?? "") ? asDate(v) : null;
                  return (
                    <td key={j} className={typeof v === "number" ? "num" : ""} title={date ? cell(v) : undefined}>
                      {date ? date.toLocaleString() : cell(v)}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
