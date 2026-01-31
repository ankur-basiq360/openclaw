import { describe, it, expect } from "vitest";
import { hasSecretRef } from "./auth-integration.js";

describe("auth-integration", () => {
  describe("hasSecretRef", () => {
    it("returns true when keyRef is present", () => {
      expect(hasSecretRef({ keyRef: "pass:test" })).toBe(true);
    });

    it("returns true when tokenRef is present", () => {
      expect(hasSecretRef({ tokenRef: "pass:test" })).toBe(true);
    });

    it("returns false when no refs present", () => {
      expect(hasSecretRef({})).toBe(false);
    });

    it("returns false when refs are empty strings", () => {
      expect(hasSecretRef({ keyRef: "", tokenRef: "  " })).toBe(false);
    });

    it("returns true when both refs are present", () => {
      expect(hasSecretRef({ keyRef: "pass:key", tokenRef: "pass:token" })).toBe(true);
    });
  });

  // NOTE: resolveCredentialValue, resolveApiKey, resolveToken tests require
  // proper mocking of the resolver module. Due to ESM module hoisting,
  // vi.mock needs to be hoisted to the top of the file before imports.
  // For now, these are covered by integration tests that run with actual `pass`.
  //
  // TODO: Add proper mock tests using vitest's hoisting features or
  // refactor to use dependency injection for testability.
});
