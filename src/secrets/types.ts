/**
 * Secrets Backend Types
 *
 * Defines the interface for pluggable secrets backends that allow
 * OpenClaw to retrieve credentials from external secret managers.
 */

export type SecretsBackendType = "pass" | "vault" | "keyring" | "env" | "file" | "ganesh";

export type PassBackendConfig = {
  /** Custom password-store path (default: ~/.password-store) */
  storePath?: string;
  /** GPG binary path (default: gpg) */
  gpgPath?: string;
};

export type VaultBackendConfig = {
  /** Vault server address */
  address?: string;
  /** Vault token (or use tokenEnv) */
  token?: string;
  /** Environment variable containing Vault token */
  tokenEnv?: string;
  /** Vault namespace (enterprise) */
  namespace?: string;
  /** KV secrets engine mount path (default: secret) */
  mountPath?: string;
  /** KV version: 1 or 2 (default: 2) */
  kvVersion?: 1 | 2;
};

export type KeyringBackendConfig = {
  /** Service name for keyring entries (default: openclaw) */
  service?: string;
};

export type GaneshBackendConfig = {
  /** Path to Ganesh vault directory (default: ~/.ganesh/vault) */
  vaultPath?: string;
  /** Auto-unlock on first access (default: true) */
  autoUnlock?: boolean;
};

export type SecretsBackendConfig = {
  /** Backend type */
  backend: SecretsBackendType;

  /** Pass-specific options */
  pass?: PassBackendConfig;

  /** Vault-specific options */
  vault?: VaultBackendConfig;

  /** Keyring-specific options */
  keyring?: KeyringBackendConfig;

  /** Ganesh Vault-specific options */
  ganesh?: GaneshBackendConfig;
};

/**
 * Parsed secret reference
 *
 * Format: "backend:path" or just "path" (uses configured default)
 * Examples:
 *   - "pass:openclaw/telegram-token"
 *   - "vault:secret/data/openclaw/api-key"
 *   - "env:ANTHROPIC_API_KEY"
 *   - "keyring:openclaw/telegram"
 */
export type SecretRef = {
  /** Backend to use (inferred from prefix or config default) */
  backend: SecretsBackendType;
  /** Path within the backend */
  path: string;
  /** Optional field for backends that return objects (e.g., Vault) */
  field?: string;
};

/**
 * Result of a secret resolution attempt
 */
export type SecretResolutionResult = {
  ok: boolean;
  value?: string;
  error?: string;
  cached?: boolean;
};

/**
 * Interface that all secrets backends must implement
 */
export interface SecretsBackend {
  /** Backend identifier */
  readonly name: SecretsBackendType;

  /**
   * Check if this backend is available and properly configured
   */
  isAvailable(): Promise<boolean>;

  /**
   * Resolve a secret path to its value
   *
   * @param path - Path within the backend (format depends on backend)
   * @param field - Optional field name for backends that return objects
   * @returns The secret value, or null if not found
   */
  resolve(path: string, field?: string): Promise<string | null>;

  /**
   * Store a secret (optional - some backends are read-only)
   *
   * @param path - Path within the backend
   * @param value - Secret value to store
   * @returns true if stored successfully
   */
  store?(path: string, value: string): Promise<boolean>;

  /**
   * List available secrets (optional - for discovery/debugging)
   *
   * @param prefix - Optional path prefix to filter
   * @returns List of secret paths
   */
  list?(prefix?: string): Promise<string[]>;
}
