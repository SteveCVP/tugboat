# Contributing

Use Node.js 20 or newer. Create a focused branch, add a failing behavioral test
before changing runtime behavior, and run these gates before opening a pull request:

```bash
npm test
npm run test:behavior
npm pack --dry-run
```

Do not commit credentials, private mission data, generated bundles, or local
worktree paths. Keep Tugboat dependency-free unless a dependency is necessary
and its security and portability cost is explicitly accepted.
