import { defineConfig } from 'tsup';

// One self-contained file, so the CLI can be copied to a machine with nothing but Node.
export default defineConfig({
  entry: { minotaur: 'src/bin.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node22',
  clean: true,
  sourcemap: true,
  splitting: false,
  noExternal: [/.*/],
  // Ink connects to React DevTools only when DEV=true, for debugging Ink itself; it is not installed.
  esbuildPlugins: [
    {
      name: 'no-ink-devtools',
      setup(build) {
        build.onResolve({ filter: /^\.\/devtools\.js$/ }, (args) =>
          /[\\/]ink[\\/]build$/.test(args.resolveDir) ? { path: 'ink-devtools', namespace: 'empty' } : undefined,
        );
        build.onLoad({ filter: /.*/, namespace: 'empty' }, () => ({ contents: 'export {};', loader: 'js' }));
      },
    },
  ],
  banner: {
    js: "#!/usr/bin/env node\nimport { createRequire as __createRequire } from 'node:module';\nconst require = __createRequire(import.meta.url);",
  },
});
