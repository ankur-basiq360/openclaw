/**
 * Secrets Integration Tests
 *
 * These tests verify end-to-end secret resolution and detect plaintext secrets
 * in configuration files. Run with actual backends when available.
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeAll } from "vitest";
import { resolveCredentialValue, resolveApiKey, resolveToken } from "./auth-integration.js";
import { GaneshBackend } from "./backends/ganesh.js";
import { resolveSecret } from "./resolver.js";

// ============================================================================
// Helpers
// ============================================================================

const _isAgeAvailable = (): boolean => {
  try {
    execSync("which age", { stdio: "ignore" });
    execSync("which age-keygen", { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};

const isGaneshVaultAvailable = (): boolean => {
  const vaultPath = path.join(os.homedir(), ".ganesh", "vault");
  return (
    fs.existsSync(path.join(vaultPath, "manifest.json")) &&
    fs.existsSync(path.join(vaultPath, "secrets.age")) &&
    fs.existsSync(path.join(vaultPath, "identity.key"))
  );
};

// ============================================================================
// Secret Resolution Tests
// ============================================================================

describe("Secret Resolution Integration", () => {
  describe("resolveSecret", () => {
    it("returns error for unknown backend", async () => {
      const result = await resolveSecret("unknown:some/secret");
      expect(result.ok).toBe(false);
      // Error can be "unknown backend" or "Backend X is not available" depending on fallback behavior
      expect(result.error).toBeTruthy();
    });

    it("returns error for invalid reference format", async () => {
      const result = await resolveSecret("invalid-no-colon");
      expect(result.ok).toBe(false);
    });

    it.skipIf(!isGaneshVaultAvailable())("resolves ganesh: refs", async () => {
      const result = await resolveSecret("ganesh:openclaw/telegram-bot-token");
      expect(result.ok).toBe(true);
      expect(result.value).toBeTruthy();
      expect(result.value?.length).toBeGreaterThan(10);
    });
  });

  describe("resolveCredentialValue", () => {
    it("prefers direct value when no ref provided", async () => {
      const result = await resolveCredentialValue("direct-value", undefined);
      expect(result).toEqual({ value: "direct-value", fromRef: false });
    });

    it("returns null when neither value nor ref provided", async () => {
      const result = await resolveCredentialValue(undefined, undefined);
      expect(result).toBeNull();
    });

    it("returns null when both are empty", async () => {
      const result = await resolveCredentialValue("", "");
      expect(result).toBeNull();
    });

    it.skipIf(!isGaneshVaultAvailable())(
      "resolves ref and prefers it over direct value",
      async () => {
        const result = await resolveCredentialValue(
          "fallback-value",
          "ganesh:openclaw/telegram-bot-token",
        );
        expect(result?.fromRef).toBe(true);
        expect(result?.value).not.toBe("fallback-value");
      },
    );
  });

  describe("resolveApiKey", () => {
    it("resolves direct key", async () => {
      const cred = {
        type: "api_key" as const,
        provider: "test",
        key: "sk-test-key",
      };
      const result = await resolveApiKey(cred);
      expect(result).toBe("sk-test-key");
    });

    it.skipIf(!isGaneshVaultAvailable())("resolves keyRef", async () => {
      const cred = {
        type: "api_key" as const,
        provider: "test",
        key: "",
        keyRef: "ganesh:anthropic/api-key",
      };
      const result = await resolveApiKey(cred);
      expect(result).toBeTruthy();
      expect(result?.startsWith("sk-ant-")).toBe(true);
    });
  });

  describe("resolveToken", () => {
    it("resolves direct token", async () => {
      const cred = {
        type: "token" as const,
        provider: "test",
        token: "test-token-123",
      };
      const result = await resolveToken(cred);
      expect(result).toBe("test-token-123");
    });

    it.skipIf(!isGaneshVaultAvailable())("resolves tokenRef", async () => {
      const cred = {
        type: "token" as const,
        provider: "anthropic",
        token: "",
        tokenRef: "ganesh:anthropic/api-key",
      };
      const result = await resolveToken(cred);
      expect(result).toBeTruthy();
      expect(result?.startsWith("sk-ant-")).toBe(true);
    });
  });
});

// ============================================================================
// Ganesh Backend Integration Tests
// ============================================================================

describe("Ganesh Backend Integration", () => {
  let backend: GaneshBackend;

  beforeAll(() => {
    backend = new GaneshBackend();
  });

  it.skipIf(!isGaneshVaultAvailable())("isAvailable returns true for existing vault", async () => {
    const available = await backend.isAvailable();
    expect(available).toBe(true);
  });

  it.skipIf(!isGaneshVaultAvailable())("lists all secrets", async () => {
    const secrets = await backend.list();
    expect(Array.isArray(secrets)).toBe(true);
    expect(secrets.length).toBeGreaterThan(0);
  });

  it.skipIf(!isGaneshVaultAvailable())("resolves known secrets", async () => {
    // These secrets should exist from the migration
    const telegramToken = await backend.resolve("openclaw/telegram-bot-token");
    expect(telegramToken).toBeTruthy();

    const anthropicKey = await backend.resolve("anthropic/api-key");
    expect(anthropicKey).toBeTruthy();
    expect(anthropicKey?.startsWith("sk-ant-")).toBe(true);
  });

  it.skipIf(!isGaneshVaultAvailable())("returns null for missing secrets", async () => {
    const result = await backend.resolve("nonexistent/secret-12345");
    expect(result).toBeNull();
  });
});

// ============================================================================
// Config Security Scanning Tests
// ============================================================================

describe("Config Security Scanning", () => {
  // Patterns that indicate plaintext secrets
  const SECRET_PATTERNS = [
    // Anthropic API keys
    /sk-ant-[a-zA-Z0-9_-]{20,}/,
    // OpenAI API keys
    /sk-[a-zA-Z0-9]{48,}/,
    // Telegram bot tokens (number:alphanumeric)
    /\d{9,}:[A-Za-z0-9_-]{35}/,
    // Generic API keys (long alphanumeric strings that look like keys)
    /"(api[_-]?key|apikey|secret|token|password)":\s*"[a-zA-Z0-9_-]{32,}"/i,
  ];

  const _CONFIG_FILES = [
    path.join(os.homedir(), ".openclaw", "openclaw.json"),
    path.join(os.homedir(), ".openclaw", "agents", "main", "agent", "auth-profiles.json"),
  ];

  /**
   * Check if a file contains plaintext secrets
   * Returns array of found patterns (should be empty for secure configs)
   */
  function scanForSecrets(filePath: string): string[] {
    if (!fs.existsSync(filePath)) {
      return [];
    }

    const content = fs.readFileSync(filePath, "utf-8");
    const found: string[] = [];

    for (const pattern of SECRET_PATTERNS) {
      const matches = content.match(pattern);
      if (matches) {
        // Redact the actual secret in the report
        const redacted = matches[0].slice(0, 15) + "..." + matches[0].slice(-4);
        found.push(`${pattern.source}: ${redacted}`);
      }
    }

    return found;
  }

  it("openclaw.json should not contain plaintext secrets", () => {
    const configPath = path.join(os.homedir(), ".openclaw", "openclaw.json");
    if (!fs.existsSync(configPath)) {
      console.log("Skipping: openclaw.json not found");
      return;
    }

    const found = scanForSecrets(configPath);

    if (found.length > 0) {
      console.error("⚠️  Plaintext secrets found in openclaw.json:");
      found.forEach((f) => console.error(`  - ${f}`));
    }

    expect(found).toEqual([]);
  });

  it("auth-profiles.json should not contain plaintext secrets", () => {
    const configPath = path.join(
      os.homedir(),
      ".openclaw",
      "agents",
      "main",
      "agent",
      "auth-profiles.json",
    );
    if (!fs.existsSync(configPath)) {
      console.log("Skipping: auth-profiles.json not found");
      return;
    }

    const found = scanForSecrets(configPath);

    if (found.length > 0) {
      console.error("⚠️  Plaintext secrets found in auth-profiles.json:");
      found.forEach((f) => console.error(`  - ${f}`));
    }

    expect(found).toEqual([]);
  });

  it("should use secret refs instead of plaintext values", () => {
    const configPath = path.join(os.homedir(), ".openclaw", "openclaw.json");
    if (!fs.existsSync(configPath)) {
      console.log("Skipping: openclaw.json not found");
      return;
    }

    const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));

    // Check Telegram uses botTokenRef
    if (config.channels?.telegram?.enabled) {
      expect(config.channels.telegram.botTokenRef).toBeTruthy();
      expect(config.channels.telegram.botToken).toBeFalsy();
    }
  });

  it("auth-profiles should use tokenRef/keyRef for credentials", () => {
    const configPath = path.join(
      os.homedir(),
      ".openclaw",
      "agents",
      "main",
      "agent",
      "auth-profiles.json",
    );
    if (!fs.existsSync(configPath)) {
      console.log("Skipping: auth-profiles.json not found");
      return;
    }

    const store = JSON.parse(fs.readFileSync(configPath, "utf-8"));

    for (const [_profileId, profile] of Object.entries(store.profiles || {})) {
      const p = profile as Record<string, unknown>;

      if (p.type === "token") {
        // Should have tokenRef and empty/missing token
        expect(p.tokenRef).toBeTruthy();
        expect(p.token).toBeFalsy();
      }

      if (p.type === "api_key") {
        // Should have keyRef and empty/missing key
        expect(p.keyRef).toBeTruthy();
        expect(p.key).toBeFalsy();
      }
    }
  });
});
