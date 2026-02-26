# wopr-plugin-tools

`@wopr-network/wopr-plugin-tools` — HTTP fetch and shell exec A2A tools for WOPR bots.

## Commands

```bash
npm run build     # tsc
npm run dev       # tsc --watch
npm run check     # biome check + tsc --noEmit (run before committing)
npm run lint:fix  # biome check --fix src/
npm run format    # biome format --write src/
npm test          # vitest run
```

**Linter/formatter is Biome.** Never add ESLint/Prettier config.

## Architecture

```
src/
  index.ts              # Plugin entry — exports WOPRPlugin default
  http-fetch.ts         # http_fetch A2A tool handler
  exec-command.ts       # exec_command A2A tool handler
  security-policy.ts    # Domain/command allowlist/blocklist enforcement
  types.ts              # Re-exports from @wopr-network/plugin-types + local types
tests/
  index.test.ts         # Plugin lifecycle (init, shutdown, manifest)
  http-fetch.test.ts    # HTTP fetch handler tests
  exec-command.test.ts  # Exec command handler tests
  security-policy.test.ts # Security policy unit tests
```

## Plugin Contract

This plugin imports ONLY from `@wopr-network/plugin-types` — never from wopr core internals.

```typescript
import type { WOPRPlugin, WOPRPluginContext } from "@wopr-network/plugin-types";
```

The default export must satisfy `WOPRPlugin`. The plugin receives `WOPRPluginContext` at `init()` time.

## Key Conventions

- Node >= 22, ESM (`"type": "module"`)
- Biome for lint + format
- `npm run check` must pass before every commit
- Conventional commits with issue key: `feat: add X (WOP-NNN)`

## Issue Tracking

All issues in **Linear** (team: WOPR). Issue descriptions start with `**Repo:** wopr-network/wopr-plugin-tools`.
