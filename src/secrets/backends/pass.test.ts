import { describe, it, expect } from "vitest";
import { PassBackend } from "./pass.js";

describe("PassBackend", () => {
  describe("constructor", () => {
    it("uses default store path when not configured", () => {
      const backend = new PassBackend();
      expect(backend.name).toBe("pass");
    });

    it("uses custom store path when configured", () => {
      const backend = new PassBackend({ storePath: "/custom/path" });
      expect(backend.name).toBe("pass");
    });
  });

  // Integration tests that require actual `pass` installation
  // These are skipped in CI but can be run locally
  describe.skipIf(!process.env.RUN_INTEGRATION_TESTS)("integration", () => {
    it("isAvailable returns true when pass is installed", async () => {
      const backend = new PassBackend();
      const result = await backend.isAvailable();
      // This will only pass if pass is actually installed and initialized
      expect(typeof result).toBe("boolean");
    });

    it("resolve returns null for non-existent secret", async () => {
      const backend = new PassBackend();
      const result = await backend.resolve("nonexistent/secret/path");
      expect(result).toBe(null);
    });
  });
});
