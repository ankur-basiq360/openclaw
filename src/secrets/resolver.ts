/**
 * Secrets Resolver
 *
 * Handles parsing secret references and resolving them through
 * the appropriate backend.
 */

import type {
  SecretsBackend,
  SecretsBackendConfig,
  SecretsBackendType,
  SecretRef,
  SecretResolutionResult,
} from "./types.js";
import { PassBackend } from "./backends/pass.js";

// In-memory cache for resolved secrets (per-process lifetime)
const secretsCache = new Map<string, { value: string; resolvedAt: number }>();

// Cache TTL in milliseconds (5 minutes)
const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Parse a secret reference string into its components
 *
 * Formats:
 *   - "pass:path/to/secret" -> { backend: "pass", path: "path/to/secret" }
 *   - "vault:secret/data/app#field" -> { backend: "vault", path: "secret/data/app", field: "field" }
 *   - "env:VAR_NAME" -> { backend: "env", path: "VAR_NAME" }
 *   - "path/to/secret" -> { backend: <default>, path: "path/to/secret" }
 */
export function parseSecretRef(
  ref: string,
  defaultBackend: SecretsBackendType = "file",
): SecretRef {
  // Check for backend prefix
  const prefixMatch = ref.match(/^(pass|vault|keyring|env|file):(.+)$/);

  let backend: SecretsBackendType;
  let pathWithField: string;

  if (prefixMatch) {
    backend = prefixMatch[1] as SecretsBackendType;
    pathWithField = prefixMatch[2];
  } else {
    backend = defaultBackend;
    pathWithField = ref;
  }

  // Check for field suffix (Vault-style: path#field)
  const fieldMatch = pathWithField.match(/^(.+)#(\w+)$/);
  if (fieldMatch) {
    return {
      backend,
      path: fieldMatch[1],
      field: fieldMatch[2],
    };
  }

  return { backend, path: pathWithField };
}

/**
 * Check if a value looks like a secret reference
 */
export function isSecretRef(value: unknown): value is string {
  if (typeof value !== "string") return false;
  // Must have a recognized prefix
  return /^(pass|vault|keyring|env):/.test(value);
}

/**
 * Create a backend instance from config
 */
export function createBackend(config: SecretsBackendConfig): SecretsBackend {
  switch (config.backend) {
    case "pass":
      return new PassBackend(config.pass);
    case "vault":
      // TODO: Implement VaultBackend
      throw new Error("Vault backend not yet implemented");
    case "keyring":
      // TODO: Implement KeyringBackend
      throw new Error("Keyring backend not yet implemented");
    case "env":
      // TODO: Implement EnvBackend
      throw new Error("Env backend not yet implemented");
    case "file":
      // File backend is the default (no external resolution needed)
      throw new Error("File backend does not support resolution");
    default:
      throw new Error(`Unknown secrets backend: ${config.backend}`);
  }
}

/**
 * Backend instances cache
 */
const backendInstances = new Map<SecretsBackendType, SecretsBackend>();

/**
 * Get or create a backend instance
 */
export function getBackend(
  type: SecretsBackendType,
  config?: SecretsBackendConfig,
): SecretsBackend {
  let backend = backendInstances.get(type);
  if (!backend) {
    const backendConfig: SecretsBackendConfig = config || { backend: type };
    backend = createBackend(backendConfig);
    backendInstances.set(type, backend);
  }
  return backend;
}

/**
 * Resolve a secret reference to its value
 */
export async function resolveSecret(
  ref: string,
  config?: SecretsBackendConfig,
): Promise<SecretResolutionResult> {
  // Check cache first
  const cacheKey = ref;
  const cached = secretsCache.get(cacheKey);
  if (cached && Date.now() - cached.resolvedAt < CACHE_TTL_MS) {
    return { ok: true, value: cached.value, cached: true };
  }

  try {
    const parsed = parseSecretRef(ref, config?.backend || "pass");

    // Get backend
    const backend = getBackend(parsed.backend, config);

    // Check availability
    const available = await backend.isAvailable();
    if (!available) {
      return {
        ok: false,
        error: `Backend "${parsed.backend}" is not available`,
      };
    }

    // Resolve
    const value = await backend.resolve(parsed.path, parsed.field);
    if (value === null) {
      return {
        ok: false,
        error: `Secret not found: ${ref}`,
      };
    }

    // Cache the result
    secretsCache.set(cacheKey, { value, resolvedAt: Date.now() });

    return { ok: true, value };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, error: message };
  }
}

/**
 * Clear the secrets cache (useful for testing or manual refresh)
 */
export function clearSecretsCache(): void {
  secretsCache.clear();
}

/**
 * Resolve all secret refs in an object (shallow, single level)
 *
 * Looks for fields ending in "Ref" and resolves them, placing
 * the result in the corresponding field without "Ref".
 *
 * Example:
 *   { tokenRef: "pass:openclaw/token" }
 *   -> { tokenRef: "pass:openclaw/token", token: "actual-value" }
 */
export async function resolveSecretRefs<T extends Record<string, unknown>>(
  obj: T,
  config?: SecretsBackendConfig,
): Promise<T & { _secretErrors?: Record<string, string> }> {
  const result = { ...obj } as T & { _secretErrors?: Record<string, string> };
  const errors: Record<string, string> = {};

  for (const [key, value] of Object.entries(obj)) {
    // Check for *Ref fields
    if (key.endsWith("Ref") && typeof value === "string") {
      const targetKey = key.slice(0, -3); // Remove "Ref" suffix
      const resolution = await resolveSecret(value, config);

      if (resolution.ok && resolution.value) {
        (result as Record<string, unknown>)[targetKey] = resolution.value;
      } else {
        errors[key] = resolution.error || "Unknown error";
      }
    }
  }

  if (Object.keys(errors).length > 0) {
    result._secretErrors = errors;
  }

  return result;
}
