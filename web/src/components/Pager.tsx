/** Prev / next pager for offset-based API lists. */
export function Pager({ offset, total, onChange, page }: { offset: number; total: number; onChange: (o: number) => void; page: number }) {
  if (total <= page) return null;
  return (
    <div className="pager" role="group" aria-label="Pages">
      <button type="button" className="small" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - page))}>
        ← Prev
      </button>
      <span className="small-text num">
        {offset + 1}–{Math.min(total, offset + page)} of {total.toLocaleString()}
      </span>
      <button type="button" className="small" disabled={offset + page >= total} onClick={() => onChange(offset + page)}>
        Next →
      </button>
    </div>
  );
}
