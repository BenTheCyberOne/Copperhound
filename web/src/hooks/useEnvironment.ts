// The environment (AD domain / Entra tenant) findings and reports are scoped
// to; shared by the Findings, finding and Reports pages and remembered.

import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Environment } from "../api/types";
import { readLocal, writeLocal } from "./localStore";

const KEY = "copperhound.environment";
let listeners: ((v: string) => void)[] = [];

export function useEnvironment(generation: number | null): [string, (v: string) => void, Environment[]] {
  const [env, setEnvState] = useState<string>(() => readLocal(KEY, ""));
  const [list, setList] = useState<Environment[]>([]);
  useEffect(() => {
    const l = (v: string) => setEnvState(v);
    listeners.push(l);
    return () => {
      listeners = listeners.filter((x) => x !== l);
    };
  }, []);
  useEffect(() => {
    let live = true;
    api.environments().then(
      (r) => live && setList(r),
      () => live && setList([]),
    );
    return () => {
      live = false;
    };
  }, [generation]);
  const set = (v: string) => {
    writeLocal(KEY, v);
    for (const l of listeners) l(v);
  };
  // A remembered environment that is not in this graph means "all".
  const valid = env && list.length > 0 && !list.some((e) => e.id === env) ? "" : env;
  return [valid, set, list];
}

