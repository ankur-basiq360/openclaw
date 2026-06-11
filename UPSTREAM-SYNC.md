# Syncing with Upstream OpenClaw

Our fork: `ankur-basiq360/openclaw`  
Upstream: `openclaw/openclaw`

## ⚠️ Critical Rules

1. **ALWAYS use `pnpm`** — not npm! The project declares `packageManager: pnpm@10.23.0`
   - `npm install` creates a flat node_modules layout incompatible with the build
   - If you accidentally ran npm: `rm -rf node_modules && pnpm install`
2. **Re-apply exec patch after every build**: `~/bin/fix-openclaw-exec.sh`
3. **Reinstall cedar-wasm after clean install**: `pnpm add @cedar-policy/cedar-wasm`
4. **Back up dist/ before merging**: `cp -r dist/ dist-backup-$(openclaw --version | awk '{print $2}')/`

## Merge Workflow

```bash
# 1. Backup
cp -r dist/ dist-backup-$(date +%Y%m%d)/

# 2. Fetch & merge
git fetch upstream
git merge upstream/main
# Resolve conflicts (see conflict guide below)

# 3. Build (MUST use pnpm)
pnpm install
pnpm add @cedar-policy/cedar-wasm      # our custom dep, not in upstream package.json
pnpm run build

# 4. Post-build patches
~/bin/fix-openclaw-exec.sh              # exec security default: allowlist → full

# 5. Smoke test
node -e "console.log('build OK')"
openclaw --version

# 6. Deploy
sudo systemctl restart openclaw
openclaw status
```

## Conflict Resolution Guide

### Always take upstream (we don't use these)

- `extensions/feishu/` — Feishu/Lark channel (not used)

### Keep our additions, merge with upstream

- `src/channels/plugins/types.adapters.ts` — keep `resolveAccountAsync`, add upstream's new fields
- `src/gateway/server-channels.ts` — keep async account resolution fallback
- `extensions/telegram/src/channel.ts` — check if upstream now handles SecretRef natively (as of 3.8, it does via `normalizeResolvedSecretInputString`)

### Take upstream, verify compat

- `src/agents/auth-profiles/order.ts` — upstream refactors frequently, take theirs, verify secrets backend
- `src/agents/bash-tools.exec.ts` — our policy gate import must survive (line ~6)

### Our custom files (should never conflict)

- `src/infra/ganesh-policy-gate.ts` — Cedar policy evaluation
- `src/infra/ganesh-cedar-engine.ts` — Cedar WASM engine
- `src/secrets/backends/ganesh.ts` — Ganesh vault backend
- `src/secrets/types.ts` — secrets type definitions

## Our Custom Commits

### Security (Cedar Policy Gate)

- `f74f39437` feat: add Ganesh policy gate for exec tool
- `96a2b0963` feat: Cedar policy engine for command execution
- `81c844934` feat: tiered agent permissions via Cedar RBAC
- `b63475bbc` feat: policies.d/ directory for modular Cedar policies
- `6166e03e4` fix: Cedar WASM - resolve to package root then nodejs/ subdir (+ 4 related fixes)

### Secrets Backend (Ganesh Vault)

- `864f99c5d` feat(secrets): add pluggable secrets backend infrastructure
- `4dc26da7c` feat(secrets): Add Tier 3 MFA support to Ganesh backend
- `96c9eb1f0` feat(secrets): Switch MFA to inline buttons
- `a3df38b4a` feat(secrets): Support mode-based tier overrides
- `c0ef0479b` feat: wire credential broker into ganesh secrets backend

### Merge History

- `a452c73b7` merge: upstream v2026.3.2 (Mar 5, 2026)
- `93fbd4722` merge: upstream v2026.3.8 (Mar 9, 2026) — 5 conflicts, all resolved

## Post-Build Patch: fix-openclaw-exec.sh

The bundler sometimes overrides our `tools.exec.security: "full"` config with the default `"allowlist"`. The patch script sed-replaces this in the dist chunks. **Must run after every build.**

If the pattern changes in future builds, update `~/bin/fix-openclaw-exec.sh`.

## Revert Script

If anything goes wrong after upgrade:

```bash
bash ~/bin/revert-openclaw.sh
```

This restores the previous dist/ backup and restarts OpenClaw.

## Known Issues

- **npm vs pnpm**: Using `npm install` instead of `pnpm install` was the #1 post-merge failure (Mar 9 upgrade). The flat node_modules layout breaks pnpm-native build scripts.
- **@cedar-policy/cedar-wasm**: Not in upstream's package.json. Must be explicitly added after clean installs.
- **Doctor warnings about safeBins profiles**: Cosmetic (new in 3.7+). Our safeBins work fine, they just lack the new "profile" metadata.

## Merge 2026.6.6 (2026-06-10) — branch merge/upstream-2026.6.6, commit 30538c67dd1

Conflicts (7), all resolved:
- pnpm-lock.yaml, package.json — upstream + re-added postbuild(fix-bundler-circular-deps) + @cedar-policy/cedar-wasm
- src/agents/bash-tools.exec.ts — upstream + reinserted Cedar policy gate (import + deny block)
- src/agents/model-selection.ts — TOOK UPSTREAM (includeAgentPrimary replaces our subagent-ref canonicalization; REGRESSION-TEST subagent model resolution)
- src/config/plugin-auto-enable.ts + .test.ts — TOOK UPSTREAM (split into modules; .test.ts deleted upstream; our auto-enable fix absorbed)
- src/gateway/call.ts — TOOK UPSTREAM (resolver injection went native)

Build: pnpm install --no-frozen-lockfile (lockfile needed cedar-wasm); pnpm add cedar-wasm 4.10.0;
node scripts/tsdown-build.mjs + runtime-postbuild.mjs → OK. `node dist/index.js --version` = OpenClaw 2026.6.2 (30538c6).
Cedar gate confirmed in dist/bash-tools-*.js.

⚠ EXEC PATCH FINDING: ~/bin/fix-openclaw-exec.sh referenced here is MISSING on disk. dist still contains
`security: "allowlist"` (4 sites in commands-handlers.runtime). BUT live openclaw.json sets `"security":"full"`
explicitly (config-level). Whether the dist default matters at runtime is a REGRESSION-TEST item for the
appliance phase — do NOT assume the post-build sed is still needed or still missing-critical until exec
behavior is verified live. This was merge-assessment risk #1.

Delta extracted as patch series → ganesh-appliance/patches/ (D6, fork now "upstream + patches").
