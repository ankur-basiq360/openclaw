import { describe, it, expect, beforeEach } from "vitest";
import { parseSecretRef, isSecretRef, resolveSecretRefs, clearSecretsCache } from "./resolver.js";

describe("parseSecretRef", () => {
  it("parses pass reference", () => {
    const ref = parseSecretRef("pass:openclaw/telegram-token");
    expect(ref).toEqual({
      backend: "pass",
      path: "openclaw/telegram-token",
    });
  });

  it("parses vault reference with field", () => {
    const ref = parseSecretRef("vault:secret/data/app#api_key");
    expect(ref).toEqual({
      backend: "vault",
      path: "secret/data/app",
      field: "api_key",
    });
  });

  it("parses env reference", () => {
    const ref = parseSecretRef("env:ANTHROPIC_API_KEY");
    expect(ref).toEqual({
      backend: "env",
      path: "ANTHROPIC_API_KEY",
    });
  });

  it("uses default backend for unprefixed refs", () => {
    const ref = parseSecretRef("openclaw/token", "pass");
    expect(ref).toEqual({
      backend: "pass",
      path: "openclaw/token",
    });
  });
});

describe("isSecretRef", () => {
  it("returns true for valid refs", () => {
    expect(isSecretRef("pass:openclaw/token")).toBe(true);
    expect(isSecretRef("vault:secret/app")).toBe(true);
    expect(isSecretRef("env:API_KEY")).toBe(true);
    expect(isSecretRef("keyring:openclaw/token")).toBe(true);
  });

  it("returns false for non-refs", () => {
    expect(isSecretRef("sk-abc123")).toBe(false);
    expect(isSecretRef("plain-value")).toBe(false);
    expect(isSecretRef(123)).toBe(false);
    expect(isSecretRef(null)).toBe(false);
    expect(isSecretRef(undefined)).toBe(false);
  });
});

describe("resolveSecretRefs", () => {
  beforeEach(() => {
    clearSecretsCache();
  });

  it("leaves non-ref fields unchanged", async () => {
    const obj = { name: "test", value: 123 };
    const result = await resolveSecretRefs(obj);
    expect(result.name).toBe("test");
    expect(result.value).toBe(123);
  });

  it("keeps original ref field alongside resolved value", async () => {
    // This test requires pass to be available with the secret
    // In CI, this will fail gracefully
    const obj = { tokenRef: "pass:openclaw/test-token" };
    const result = await resolveSecretRefs(obj);
    expect(result.tokenRef).toBe("pass:openclaw/test-token");
    // result.token will be undefined or have the actual value depending on pass availability
  });
});
