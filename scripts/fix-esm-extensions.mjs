/**
 * Append `.js` to extensionless relative specifiers in the emitted output.
 *
 * The source deliberately uses extensionless relative imports (`./bytes`)
 * because that is what Metro — and therefore the React Native app that consumes
 * this package from source — resolves. Node's ESM loader requires full
 * specifiers, so the published build gets them added here.
 *
 * Keeping the workaround in twelve lines of build script is the cheaper half of
 * the trade: the alternative is a resolver shim in every consuming bundler.
 */

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const DIST = new URL('../dist/', import.meta.url).pathname;

// `from './x'`, `import('./x')`, `export * from '../x'` — but not './x.js',
// './x.json', or anything already carrying an extension.
const SPECIFIER = /((?:from|import)\s*\(?\s*)(['"])(\.\.?\/[^'"]*?)(\2)/g;

function fix(file) {
  const src = readFileSync(file, 'utf8');
  const out = src.replace(SPECIFIER, (match, lead, quote, spec) => {
    if (/\.[a-zA-Z0-9]+$/.test(spec)) return match;
    return `${lead}${quote}${spec}.js${quote}`;
  });
  if (out !== src) writeFileSync(file, out);
}

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (/\.(js|d\.ts)$/.test(entry.name)) fix(path);
  }
}

walk(DIST);
