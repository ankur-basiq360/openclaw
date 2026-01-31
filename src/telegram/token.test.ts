/**
 * Telegram Token Resolution Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { resolveTelegramToken, resolveTelegramTokenAsync } from "./token.js";
import type { OpenClawConfig } from "../config/config.js";

// Mock the secrets resolver
vi.mock("../secrets/resolver.js", () => ({
  resolveSecret: vi.fn(),
}));

import { resolveSecret } from "../secrets/resolver.js";

describe("resolveTelegramToken", () => {
  describe("sync version", () => {
    it("returns token from config", () => {
      const cfg = {
        channels: {
          telegram: {
            botToken: "test-token-123",
          },
        },
      } as OpenClawConfig;

      const result = resolveTelegramToken(cfg);
      expect(result.token).toBe("test-token-123");
      expect(result.source).toBe("config");
    });

    it("returns empty when no token configured", () => {
      const cfg = {
        channels: {
          telegram: {
            enabled: true,
          },
        },
      } as OpenClawConfig;

      const result = resolveTelegramToken(cfg);
      expect(result.token).toBe("");
      expect(result.source).toBe("none");
    });

    it("returns token from environment", () => {
      const originalEnv = process.env.TELEGRAM_BOT_TOKEN;
      process.env.TELEGRAM_BOT_TOKEN = "env-token-456";

      try {
        const cfg = { channels: { telegram: {} } } as OpenClawConfig;
        const result = resolveTelegramToken(cfg);
        expect(result.token).toBe("env-token-456");
        expect(result.source).toBe("env");
      } finally {
        if (originalEnv) {
          process.env.TELEGRAM_BOT_TOKEN = originalEnv;
        } else {
          delete process.env.TELEGRAM_BOT_TOKEN;
        }
      }
    });
  });

  describe("async version with secret refs", () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it("resolves token from botTokenRef", async () => {
      const mockResolveSecret = vi.mocked(resolveSecret);
      mockResolveSecret.mockResolvedValue({
        ok: true,
        value: "vault-token-789",
      });

      const cfg = {
        channels: {
          telegram: {
            botTokenRef: "ganesh:openclaw/telegram-bot-token",
          },
        },
      } as OpenClawConfig;

      const result = await resolveTelegramTokenAsync(cfg);
      expect(result.token).toBe("vault-token-789");
      expect(result.source).toBe("secretRef");
      expect(mockResolveSecret).toHaveBeenCalledWith("ganesh:openclaw/telegram-bot-token");
    });

    it("falls back to botToken when botTokenRef fails", async () => {
      const mockResolveSecret = vi.mocked(resolveSecret);
      mockResolveSecret.mockResolvedValue({
        ok: false,
        error: "Secret not found",
      });

      const cfg = {
        channels: {
          telegram: {
            botTokenRef: "ganesh:missing/secret",
            botToken: "fallback-token",
          },
        },
      } as OpenClawConfig;

      const result = await resolveTelegramTokenAsync(cfg);
      expect(result.token).toBe("fallback-token");
      expect(result.source).toBe("config");
    });

    it("uses botToken when no botTokenRef configured", async () => {
      const cfg = {
        channels: {
          telegram: {
            botToken: "direct-token",
          },
        },
      } as OpenClawConfig;

      const result = await resolveTelegramTokenAsync(cfg);
      expect(result.token).toBe("direct-token");
      expect(result.source).toBe("config");
    });

    it("returns empty when all resolution methods fail", async () => {
      const mockResolveSecret = vi.mocked(resolveSecret);
      mockResolveSecret.mockResolvedValue({
        ok: false,
        error: "Secret not found",
      });

      const cfg = {
        channels: {
          telegram: {
            botTokenRef: "ganesh:missing/secret",
          },
        },
      } as OpenClawConfig;

      const result = await resolveTelegramTokenAsync(cfg);
      expect(result.token).toBe("");
      expect(result.source).toBe("none");
    });

    it("resolves account-level botTokenRef", async () => {
      const mockResolveSecret = vi.mocked(resolveSecret);
      mockResolveSecret.mockResolvedValue({
        ok: true,
        value: "account-vault-token",
      });

      const cfg = {
        channels: {
          telegram: {
            accounts: {
              myaccount: {
                botTokenRef: "ganesh:accounts/myaccount/token",
              },
            },
          },
        },
      } as OpenClawConfig;

      const result = await resolveTelegramTokenAsync(cfg, { accountId: "myaccount" });
      expect(result.token).toBe("account-vault-token");
      expect(result.source).toBe("secretRef");
    });
  });
});
