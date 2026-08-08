// Minimal module-resolution hook so the e2ee unit tests can run on Node's
// built-in test runner with zero extra dependencies (the app has no JS test
// runner configured). The source uses extensionless relative imports
// (`./bytes`) that Node's ESM loader won't resolve on its own; this appends
// `.ts` when the target exists. Type-only imports (`./keys`, `./api`) are
// stripped by Node before resolution, so they never reach this hook.
//
// Run via:  node --import ./src/services/e2ee/__tests__/nodeHooks.mjs --test '<glob>'
import { registerHooks } from 'node:module';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('.') && !/\.[mc]?[jt]s$/.test(specifier) && context.parentURL) {
      const candidate = new URL(`${specifier}.ts`, context.parentURL);
      if (existsSync(fileURLToPath(candidate))) {
        return nextResolve(`${specifier}.ts`, context);
      }
    }
    return nextResolve(specifier, context);
  },
});
