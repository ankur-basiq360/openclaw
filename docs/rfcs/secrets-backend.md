# RFC: Secrets Backend for OpenClaw

## Summary

Add pluggable secrets backend support to OpenClaw, allowing credentials to be stored in external secret managers (pass, HashiCorp Vault, system keyring, etc.) instead of plaintext JSON files.

## Motivation

Currently, OpenClaw stores all credentials (API keys, OAuth tokens, bot tokens) in plaintext JSON files:

- `~/.openclaw/auth-profiles.json`
- `~/.openclaw/openclaw.json` (channel tokens)

While file permissions provide some protection, this is not ideal for:

- Shared machines
- Compliance requirements
- Users who already use secret managers

## Design

### Config Schema Changes

```typescript
// src/config/types.auth.ts
export type SecretsBackendConfig = {
  /** Backend type: "pass" | "vault" | "keyring" | "env" | "file" (default) */
  backend: "pass" | "vault" | "keyring" | "env" | "file";

  /** Pass-specific options */
  pass?: {
    /** Custom password-store path (default: ~/.password-store) */
    storePath?: string;
  };

  /** Vault-specific options */
  vault?: {
    address?: string;
    token?: string; // or tokenEnv for env var name
    tokenEnv?: string;
    namespace?: string;
    mountPath?: string;
  };

  /** Keyring-specific options */
  keyring?: {
    service?: string; // default: "openclaw"
  };
};

export type AuthConfig = {
  /** Secrets backend configuration */
  secretsBackend?: SecretsBackendConfig;

  profiles?: Record<string, AuthProfileConfig>;
  // ... existing fields
};
```

### Secret References

Instead of storing plaintext values, config can reference secrets:

```json5
{
  auth: {
    secretsBackend: { backend: "pass" },
    profiles: {
      "anthropic:default": {
        provider: "anthropic",
        mode: "api_key",
        keyRef: "pass:openclaw/anthropic-key", // NEW: reference instead of value
      },
    },
  },
  channels: {
    telegram: {
      tokenRef: "pass:openclaw/telegram-bot-token", // NEW
    },
  },
}
```

### Backend Interface

```typescript
// src/secrets/backend.ts
export interface SecretsBackend {
  name: string;

  /** Resolve a secret reference to its value */
  resolve(ref: string): Promise<string | null>;

  /** Check if backend is available/configured */
  isAvailable(): Promise<boolean>;

  /** Store a secret (optional - some backends are read-only) */
  store?(key: string, value: string): Promise<boolean>;
}
```

### Implementations

1. **PassBackend** - Uses `pass show <path>`
2. **VaultBackend** - Uses HashiCorp Vault HTTP API
3. **KeyringBackend** - Uses system keyring via `keytar` or native APIs
4. **EnvBackend** - Reads from environment variables
5. **FileBackend** - Current behavior (plaintext JSON)

### Resolution Flow

```
1. Load config
2. For each credential field that ends in "Ref" (tokenRef, keyRef, etc.):
   a. Parse the reference (e.g., "pass:openclaw/telegram-bot-token")
   b. Extract backend hint and path
   c. Use configured secretsBackend (or infer from prefix)
   d. Call backend.resolve(path)
   e. Replace ref with resolved value in memory (never write back)
3. Continue with resolved credentials
```

## Implementation Plan

1. [ ] Create `src/secrets/` directory with backend interface
2. [ ] Implement PassBackend
3. [ ] Add secretsBackend to AuthConfig type
4. [ ] Modify credential loading to resolve refs
5. [ ] Add CLI commands: `openclaw secrets import`, `openclaw secrets verify`
6. [ ] Implement VaultBackend
7. [ ] Implement KeyringBackend
8. [ ] Add tests
9. [ ] Documentation

## Security Considerations

- Secrets are resolved at runtime, never persisted in plaintext
- Backend credentials (Vault token) can themselves be refs or env vars
- File backend remains default for backward compatibility
- No changes to existing configs required

## Open Questions

1. Should channel tokens (Telegram, Discord) also support refs?
2. How to handle secret rotation/refresh for OAuth tokens?
3. Should we support multiple backends simultaneously?
