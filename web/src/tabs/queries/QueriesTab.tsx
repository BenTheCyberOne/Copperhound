import { useEffect, useMemo, useState } from "react";
import { api, errorMessage } from "../../api/client";
import type { PrebuiltQuery, SavedQuery } from "../../api/types";
import { useSettings } from "../../settings/SettingsContext";
import { useApp } from "../../state/AppContext";
import { QueryEditor } from "./QueryEditor";
import { QueryLibrary, type RunRequest } from "./QueryLibrary";
import { SavedQueries } from "./SavedQueries";
import { SaveQueryDialog } from "./SaveQueryDialog";
import { useQueryRunner } from "./useQueryRunner";

const DEFAULT_QUERY = "MATCH (n {tier0:true}) RETURN n";

export function QueriesTab() {
  const { notify, editorRequest } = useApp();
  const { settings } = useSettings();
  const runner = useQueryRunner();
  const [text, setText] = useState(() => runner.recent[0]?.query ?? DEFAULT_QUERY);
  const [limit, setLimit] = useState(settings.queryLimit);
  const [filter, setFilter] = useState("");
  const [prebuilt, setPrebuilt] = useState<PrebuiltQuery[]>([]);
  const [prebuiltError, setPrebuiltError] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedQuery[]>([]);
  const [savedError, setSavedError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<{ editing: SavedQuery | null } | null>(null);

  // "Open in editor" from Findings / Zones.
  useEffect(() => {
    if (editorRequest) setText(editorRequest.text);
  }, [editorRequest]);

  // A changed default limit in Settings applies to the editor too.
  useEffect(() => setLimit(settings.queryLimit), [settings.queryLimit]);

  useEffect(() => {
    api.queries().then(setPrebuilt, (e: unknown) => setPrebuiltError(errorMessage(e)));
    api.savedQueries().then(setSaved, (e: unknown) => setSavedError(errorMessage(e)));
  }, []);

  const categories = useMemo(() => [...new Set(saved.map((q) => q.category))].sort(), [saved]);

  const run = ({ query, title }: RunRequest) => {
    setText(query);
    void runner.run(query, { title, limit });
  };

  const remove = async (q: SavedQuery) => {
    if (!window.confirm(`Delete saved query “${q.name}”?`)) return;
    try {
      await api.deleteSavedQuery(q.id);
      setSaved((s) => s.filter((x) => x.id !== q.id));
    } catch (e) {
      notify(errorMessage(e), "error");
    }
  };

  return (
    <div className="tab-body">
      <QueryEditor
        text={text}
        setText={setText}
        limit={limit}
        setLimit={setLimit}
        runner={runner}
        onRun={() => run({ query: text })}
        onSave={() => setDialog({ editing: null })}
      />

      <QueryLibrary
        prebuilt={prebuilt}
        error={prebuiltError}
        recent={runner.recent}
        onClearRecent={runner.clearRecent}
        running={runner.running}
        onRun={run}
        filter={filter}
        onFilter={setFilter}
        savedSection={
          <SavedQueries
            saved={saved}
            error={savedError}
            filter={filter}
            running={runner.running}
            onRun={run}
            onEdit={(q) => setDialog({ editing: q })}
            onDelete={(q) => void remove(q)}
          />
        }
      />

      {dialog && (
        <SaveQueryDialog
          editing={dialog.editing}
          initialQuery={text}
          categories={categories}
          onClose={() => setDialog(null)}
          onSaved={(q) => {
            setSaved((s) => [...s.filter((x) => x.id !== q.id), q]);
            setDialog(null);
            notify(`Saved “${q.name}” in ${q.category}.`);
          }}
        />
      )}
    </div>
  );
}
