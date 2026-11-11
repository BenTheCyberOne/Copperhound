/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "1" serves every API call from the in-browser mock (npm run dev:mock). */
  readonly VITE_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
