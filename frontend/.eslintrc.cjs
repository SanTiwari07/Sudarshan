// The `lint` script and all these plugins were already in package.json, but no
// config file was ever committed — so `npm run lint` failed with "couldn't find
// a configuration file" and the script had never actually run.
module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', 'node_modules', '.eslintrc.cjs'],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
    // tsc already reports unused symbols via noUnusedLocals/noUnusedParameters;
    // duplicating it here would double-report the same finding.
    '@typescript-eslint/no-unused-vars': 'off',

    // Pre-existing debt, surfaced rather than hidden. These are warnings, not
    // errors, so CI stays meaningful instead of being red from day one — but
    // they stay visible so the count can be driven down.
    //   no-explicit-any        ~11 sites, mostly API response shapes
    //   react-hooks/exhaustive-deps  2 sites
    '@typescript-eslint/no-explicit-any': 'warn',
    'react-hooks/exhaustive-deps': 'warn',

    // `while (true) { ... if (done) break; }` is the idiomatic SSE reader loop
    // in InvestigationChat.tsx, and `catch {}` there is a deliberate swallow of
    // a malformed SSE frame. Both are correct as written.
    'no-constant-condition': ['error', { checkLoops: false }],
    'no-empty': ['error', { allowEmptyCatch: true }],
  },
};
