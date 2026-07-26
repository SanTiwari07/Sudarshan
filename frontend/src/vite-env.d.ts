/// <reference types="vite/client" />

// Without this, `import.meta.env` is untyped and `tsc` (which `npm run build`
// runs before vite) fails with "Property 'env' does not exist on type
// 'ImportMeta'".

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
