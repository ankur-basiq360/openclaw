/**
 * Secrets Backend Module
 *
 * Provides pluggable secrets management for OpenClaw, allowing credentials
 * to be stored in external secret managers instead of plaintext JSON.
 *
 * @example
 * ```typescript
 * import { resolveSecret, resolveSecretRefs } from "./secrets/index.js";
 *
 * // Resolve a single secret
 * const result = await resolveSecret("pass:openclaw/api-key");
 * if (result.ok) {
 *   console.log("Secret:", result.value);
 * }
 *
 * // Resolve all refs in a config object
 * const config = { tokenRef: "pass:openclaw/token", name: "test" };
 * const resolved = await resolveSecretRefs(config);
 * // resolved.token now contains the actual value
 * ```
 */

export * from "./types.js";
export * from "./resolver.js";
export { PassBackend } from "./backends/pass.js";
