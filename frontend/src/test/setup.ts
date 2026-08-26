import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

/**
 * Unmount between tests.
 *
 * Testing Library registers this automatically, but only when Vitest is running
 * with `globals: true`. This project runs without globals, so nothing was ever
 * torn down: every `render()` in a file appended to the same document.body, and
 * a second render of the same component made `getByRole` ambiguous rather than
 * failing on the thing the test was actually about.
 *
 * Registering it here rather than per-file so a new test file inherits correct
 * isolation instead of having to remember.
 */
afterEach(() => {
  cleanup();
});
