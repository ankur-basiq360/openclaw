/**
 * Auth Profile Integration for Secrets Backend
 *
 * Provides functions to resolve secret references in auth credentials.
 */

import { resolveSecret } from "./resolver.js";
import type { SecretsBackendConfig } from "./types.js";

/**
 * Result of resolving a credential value
 */
export type CredentialResolutionResult = {
  value: string;
  fromRef: boolean;
  error?: string;
};

/**
 * Resolve a credential value, checking for ref first
 *
 * @param directValue - The direct value (e.g., cred.key)
 * @param refValue - The reference value (e.g., cred.keyRef)
 * @param config - Optional secrets backend config
 * @returns The resolved value
 */
export async function resolveCredentialValue(
  directValue: string | undefined,
  refValue: string | undefined,
  config?: SecretsBackendConfig,
): Promise<CredentialResolutionResult | null> {
  // If ref is provided, try to resolve it
  if (refValue && typeof refValue === "string" && refValue.trim()) {
    const result = await resolveSecret(refValue, config);
    if (result.ok && result.value) {
      return { value: result.value, fromRef: true };
    }
    // If ref resolution failed but we have a direct value, use it with warning
    if (directValue && typeof directValue === "string" && directValue.trim()) {
      console.warn(
        `[secrets] Failed to resolve ref "${refValue}", falling back to direct value: ${result.error}`,
      );
      return { value: directValue, fromRef: false, error: result.error };
    }
    // No fallback available
    return null;
  }

  // No ref, use direct value
  if (directValue && typeof directValue === "string" && directValue.trim()) {
    return { value: directValue, fromRef: false };
  }

  return null;
}

/**
 * API key credential (matches auth-profiles types)
 */
export type ApiKeyCredentialWithRef = {
  type: "api_key";
  provider: string;
  key: string;
  keyRef?: string;
  email?: string;
};

/**
 * Token credential (matches auth-profiles types)
 */
export type TokenCredentialWithRef = {
  type: "token";
  provider: string;
  token: string;
  tokenRef?: string;
  expires?: number;
  email?: string;
};

/**
 * Check if a credential has a secret ref
 */
export function hasSecretRef(cred: { keyRef?: string; tokenRef?: string }): boolean {
  return Boolean(cred.keyRef?.trim() || cred.tokenRef?.trim());
}

/**
 * Resolve API key from credential (supports keyRef)
 */
export async function resolveApiKey(
  cred: ApiKeyCredentialWithRef,
  config?: SecretsBackendConfig,
): Promise<string | null> {
  const result = await resolveCredentialValue(cred.key, cred.keyRef, config);
  return result?.value ?? null;
}

/**
 * Resolve token from credential (supports tokenRef)
 */
export async function resolveToken(
  cred: TokenCredentialWithRef,
  config?: SecretsBackendConfig,
): Promise<string | null> {
  const result = await resolveCredentialValue(cred.token, cred.tokenRef, config);
  return result?.value ?? null;
}
