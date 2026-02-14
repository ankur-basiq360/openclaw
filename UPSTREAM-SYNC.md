# Syncing with Upstream OpenClaw

Our fork: `ankur-basiq360/openclaw`  
Upstream: `openclaw/openclaw`

## Merge Workflow

```bash
git fetch upstream
git merge upstream/main
# resolve any conflicts (see custom commits below)
npm install
npm run build
# test locally, then:
sudo systemctl restart openclaw
```

## Our Custom Commits

These are the commits we've added on top of upstream — watch for conflicts here:

- `4e8da77d8` fix: resolve build errors - import paths and type mismatches
- `3c25289d2` fix: clean up unused imports and variables
- `74f115cde` fix: remove duplicate imports in telegram/bot.ts
- `0a9cdf87e` Merge branch 'feature/ganesh-secrets'
- `a3df38b4a` feat(secrets): Support mode-based tier overrides in Ganesh backend
- `7c3d45ea8` Merge feature/secrets-backend: Ganesh vault + Tier 3 MFA
- `46231bf1b` feat(secrets): Add TOTP verification step to MFA flow
- `96c9eb1f0` feat(secrets): Switch MFA to inline buttons
- `4dc26da7c` feat(secrets): Add Tier 3 MFA support to Ganesh backend

### Key files to watch during merges

- `src/secrets/` — our ganesh backend lives here
- `src/secrets/backends/ganesh.ts` — main ganesh secrets integration
- `src/secrets/backends/ganesh.test.ts` — tests
