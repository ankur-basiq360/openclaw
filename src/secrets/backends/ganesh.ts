/**
 * Ganesh Vault Backend
 *
 * Uses the Ganesh Vault for secure secret storage with tiered access.
 * Integrates with the Ganesh Environment for AI-first secret management.
 *
 * Tier support:
 * - Tier 1: Direct access after vault unlock
 * - Tier 2: Direct access (TOTP validated at unlock)
 * - Tier 3: Requires Telegram MFA approval for each access
 *
 * @see ~/Projects/ganesh-environment
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";

import type { GaneshBackendConfig, SecretsBackend } from "../types.js";

const execAsync = promisify(exec);

// ============================================================================
// Types
// ============================================================================

type SecretTier = 1 | 2 | 3;

interface SecretGroup {
  id: string;
  name: string;
  tier: SecretTier;
  secrets: string[];
}

interface VaultManifest {
  version: number;
  groups: SecretGroup[];
  defaultTier: SecretTier;
}

interface TelegramMfaConfig {
  botToken: string;
  chatId: string;
  totpSecret: string;
  timeoutMs?: number;
}

// ============================================================================
// TOTP Implementation (RFC 6238)
// ============================================================================

function generateTotp(secret: string, time?: number): string {
  const crypto = require("node:crypto");
  const counter = Math.floor((time ?? Date.now()) / 1000 / 30);
  const buffer = Buffer.alloc(8);
  buffer.writeBigInt64BE(BigInt(counter));

  // Decode base32 secret
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const secretUpper = secret.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of secretUpper) {
    bits += base32Chars.indexOf(char).toString(2).padStart(5, "0");
  }
  const secretBytes = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < secretBytes.length; i++) {
    secretBytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }

  const hmac = crypto.createHmac("sha1", secretBytes);
  hmac.update(buffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0x0f;
  const code =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

function verifyTotp(secret: string, token: string, window = 1): boolean {
  const now = Date.now();
  for (let i = -window; i <= window; i++) {
    const time = now + i * 30 * 1000;
    if (generateTotp(secret, time) === token) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// Telegram MFA with Inline Buttons
// ============================================================================

/** Generate a unique request ID for callback routing */
function generateRequestId(): string {
  return `mfa_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

async function sendTelegramApprovalRequest(
  config: TelegramMfaConfig,
  secretId: string,
  groupName: string,
): Promise<{ ok: boolean; messageId?: number; requestId?: string; error?: string }> {
  const requestId = generateRequestId();

  const message = [
    "🔐 <b>Tier 3 Secret Access Request</b>",
    "",
    `<b>Secret:</b> <code>${secretId}</code>`,
    `<b>Group:</b> ${groupName}`,
    `<b>Requested by:</b> OpenClaw`,
    "",
    "⏳ Respond within 60 seconds",
  ].join("\n");

  // Inline keyboard with Approve/Deny buttons
  const inlineKeyboard = {
    inline_keyboard: [
      [
        { text: "✅ Approve", callback_data: `${requestId}:approve` },
        { text: "❌ Deny", callback_data: `${requestId}:deny` },
      ],
    ],
  };

  try {
    const response = await fetch(`https://api.telegram.org/bot${config.botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: config.chatId,
        text: message,
        parse_mode: "HTML",
        reply_markup: inlineKeyboard,
      }),
    });

    const data = (await response.json()) as {
      ok: boolean;
      result?: { message_id: number };
      description?: string;
    };

    if (!data.ok) {
      return { ok: false, error: data.description || "Unknown error" };
    }

    return { ok: true, messageId: data.result?.message_id, requestId };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

async function answerCallbackQuery(
  botToken: string,
  callbackQueryId: string,
  text: string,
): Promise<void> {
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        callback_query_id: callbackQueryId,
        text,
      }),
    });
  } catch {
    // Best effort
  }
}

async function editMessageAfterApproval(
  botToken: string,
  chatId: string,
  messageId: number,
  approved: boolean,
  secretId: string,
): Promise<void> {
  const status = approved ? "✅ APPROVED" : "❌ DENIED";
  const text = [
    "🔐 <b>Tier 3 Secret Access Request</b>",
    "",
    `<b>Secret:</b> <code>${secretId}</code>`,
    `<b>Status:</b> ${status}`,
    `<b>Time:</b> ${new Date().toLocaleTimeString()}`,
  ].join("\n");

  try {
    await fetch(`https://api.telegram.org/bot${botToken}/editMessageText`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        text,
        parse_mode: "HTML",
      }),
    });
  } catch {
    // Best effort
  }
}

async function pollTelegramApproval(
  config: TelegramMfaConfig,
  requestMessageId: number,
  requestId: string,
  secretId: string,
): Promise<{ approved: boolean; error?: string }> {
  const timeoutMs = config.timeoutMs ?? 60000;
  const startTime = Date.now();
  let lastUpdateId: number | undefined;

  while (Date.now() - startTime < timeoutMs) {
    try {
      const params = new URLSearchParams({
        timeout: "10",
        allowed_updates: JSON.stringify(["callback_query"]),
      });
      if (lastUpdateId) {
        params.set("offset", lastUpdateId.toString());
      }

      const response = await fetch(
        `https://api.telegram.org/bot${config.botToken}/getUpdates?${params}`,
      );
      const data = (await response.json()) as {
        ok: boolean;
        result?: Array<{
          update_id: number;
          callback_query?: {
            id: string;
            from: { id: number };
            message?: { chat: { id: number }; message_id: number };
            data?: string;
          };
        }>;
      };

      if (!data.ok) continue;

      for (const update of data.result || []) {
        lastUpdateId = update.update_id + 1;

        const callback = update.callback_query;
        if (!callback?.data) continue;
        if (String(callback.message?.chat.id) !== config.chatId) continue;

        // Check if this callback is for our request
        if (callback.data.startsWith(requestId + ":")) {
          const action = callback.data.split(":")[1];

          if (action === "approve") {
            // Acknowledge the button press
            await answerCallbackQuery(config.botToken, callback.id, "✅ Approved!");
            await editMessageAfterApproval(
              config.botToken,
              config.chatId,
              requestMessageId,
              true,
              secretId,
            );
            return { approved: true };
          } else if (action === "deny") {
            await answerCallbackQuery(config.botToken, callback.id, "❌ Denied");
            await editMessageAfterApproval(
              config.botToken,
              config.chatId,
              requestMessageId,
              false,
              secretId,
            );
            return { approved: false, error: "Request denied by user" };
          }
        }
      }
    } catch {
      // Network error, retry
    }

    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  return { approved: false, error: "Approval request timed out" };
}

// ============================================================================
// Ganesh Backend
// ============================================================================

export class GaneshBackend implements SecretsBackend {
  readonly name = "ganesh" as const;

  private config: GaneshBackendConfig;
  private vaultPath: string;
  private unlocked: boolean = false;
  private secretKey: string | null = null;
  private publicKey: string | null = null;
  private secretsCache: Map<string, string> = new Map();
  private manifest: VaultManifest | null = null;

  constructor(config: GaneshBackendConfig = {}) {
    this.config = config;
    this.vaultPath = (config.vaultPath || "~/.ganesh/vault").replace("~", os.homedir());
  }

  /**
   * Get the tier for a secret from the manifest
   */
  private getSecretTier(secretId: string): SecretTier {
    if (!this.manifest) return 1;

    for (const group of this.manifest.groups) {
      if (group.secrets.includes(secretId)) {
        return group.tier;
      }
    }

    return this.manifest.defaultTier;
  }

  /**
   * Get the group name for a secret
   */
  private getSecretGroup(secretId: string): string {
    if (!this.manifest) return "default";

    for (const group of this.manifest.groups) {
      if (group.secrets.includes(secretId)) {
        return group.name;
      }
    }

    return "default";
  }

  /**
   * Load MFA configuration for Tier 3 access
   * Returns null if MFA is not configured
   */
  private async getMfaConfig(): Promise<TelegramMfaConfig | null> {
    // Read MFA config from vault config file if it exists
    const configPath = path.join(this.vaultPath, "mfa-config.json");

    if (!fs.existsSync(configPath)) {
      // Fallback: try to use openclaw's telegram config
      // The bot token should be accessible as a Tier 1 secret
      const botToken = this.secretsCache.get("openclaw/telegram-bot-token");
      const totpPath = path.join(this.vaultPath, "totp.key");

      if (botToken && fs.existsSync(totpPath)) {
        const totpSecret = fs.readFileSync(totpPath, "utf-8").trim();
        // Chat ID from environment or hardcoded for now
        const chatId = process.env.GANESH_MFA_CHAT_ID || "8036631576"; // Ankur's Telegram ID

        return {
          botToken,
          chatId,
          totpSecret,
          timeoutMs: 60000,
        };
      }

      return null;
    }

    try {
      const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      const totpPath = path.join(this.vaultPath, "totp.key");
      const totpSecret = fs.existsSync(totpPath) ? fs.readFileSync(totpPath, "utf-8").trim() : "";

      return {
        botToken: config.botToken || this.secretsCache.get("openclaw/telegram-bot-token") || "",
        chatId: config.chatId || "8036631576",
        totpSecret,
        timeoutMs: config.timeoutMs || 60000,
      };
    } catch {
      return null;
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Check if vault directory exists with required files
      const manifestPath = path.join(this.vaultPath, "manifest.json");
      const secretsPath = path.join(this.vaultPath, "secrets.age");
      const identityPath = path.join(this.vaultPath, "identity.key");

      if (!fs.existsSync(manifestPath)) return false;
      if (!fs.existsSync(secretsPath)) return false;
      if (!fs.existsSync(identityPath)) return false;

      // Check if age is installed
      await execAsync("which age");

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Unlock the vault for this session
   * Must be called before resolve() can return tier 1-2 secrets
   */
  async unlock(): Promise<boolean> {
    if (this.unlocked) return true;

    try {
      // Read identity key
      const identityPath = path.join(this.vaultPath, "identity.key");
      this.secretKey = fs.readFileSync(identityPath, "utf-8").trim();

      // Derive public key
      const { stdout } = await execAsync(`echo "${this.secretKey}" | age-keygen -y`);
      this.publicKey = stdout.trim();

      // Load manifest for tier information
      const manifestPath = path.join(this.vaultPath, "manifest.json");
      if (fs.existsSync(manifestPath)) {
        this.manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
      }

      // Decrypt and load secrets
      await this.loadSecrets();

      this.unlocked = true;
      return true;
    } catch (error) {
      console.error("[secrets:ganesh] Failed to unlock vault:", error);
      return false;
    }
  }

  /**
   * Lock the vault, clearing cached secrets
   */
  lock(): void {
    this.unlocked = false;
    this.secretKey = null;
    this.publicKey = null;
    this.secretsCache.clear();
    this.manifest = null;
  }

  private async loadSecrets(): Promise<void> {
    if (!this.secretKey) throw new Error("Vault not unlocked");

    const secretsPath = path.join(this.vaultPath, "secrets.age");

    // Create temp identity file
    const tempIdentity = path.join(os.tmpdir(), `ganesh-id-${Date.now()}.key`);
    fs.writeFileSync(tempIdentity, this.secretKey, { mode: 0o600 });

    try {
      const { stdout } = await execAsync(`age -d -i "${tempIdentity}" "${secretsPath}"`);

      const store = JSON.parse(stdout);

      // Cache all secrets
      this.secretsCache.clear();
      for (const [id, secret] of Object.entries(store.secrets || {})) {
        const s = secret as { value: string };
        this.secretsCache.set(id, s.value);
      }
    } finally {
      // Clean up temp file
      try {
        fs.unlinkSync(tempIdentity);
      } catch {}
    }
  }

  private async saveSecrets(): Promise<void> {
    if (!this.secretKey || !this.publicKey) throw new Error("Vault not unlocked");

    const secretsPath = path.join(this.vaultPath, "secrets.age");

    // Build secrets store
    const store: { secrets: Record<string, { value: string; metadata: object }> } = {
      secrets: {},
    };

    for (const [id, value] of this.secretsCache) {
      store.secrets[id] = {
        value,
        metadata: {
          created: new Date().toISOString(),
          accessCount: 0,
        },
      };
    }

    // Encrypt and save
    const json = JSON.stringify(store);

    const { stdout, stderr } = await execAsync(
      `echo '${json.replace(/'/g, "'\\''")}' | age -r "${this.publicKey}" -o "${secretsPath}"`,
    );
  }

  async resolve(secretPath: string, _field?: string): Promise<string | null> {
    // Auto-unlock on first access
    if (!this.unlocked) {
      const ok = await this.unlock();
      if (!ok) {
        console.error("[secrets:ganesh] Vault is locked and could not auto-unlock");
        return null;
      }
    }

    // Normalize path (support both / and - separators)
    const normalizedPath = secretPath.replace(/\//g, "/");

    // Check tier
    const tier = this.getSecretTier(normalizedPath);

    // Tier 1 & 2: direct access from cache
    if (tier < 3) {
      const value = this.secretsCache.get(normalizedPath);
      return value ?? null;
    }

    // Tier 3: requires MFA approval
    return this.resolveTier3(normalizedPath);
  }

  /**
   * Resolve a Tier 3 secret with MFA approval
   */
  private async resolveTier3(secretPath: string): Promise<string | null> {
    const mfaConfig = await this.getMfaConfig();

    if (!mfaConfig) {
      console.error("[secrets:ganesh] Tier 3 secret requested but MFA not configured");
      return null;
    }

    const groupName = this.getSecretGroup(secretPath);

    console.log(`[secrets:ganesh] Requesting Tier 3 MFA approval for: ${secretPath}`);

    // Send approval request
    const sendResult = await sendTelegramApprovalRequest(mfaConfig, secretPath, groupName);

    if (!sendResult.ok || !sendResult.messageId || !sendResult.requestId) {
      console.error(`[secrets:ganesh] Failed to send MFA request: ${sendResult.error}`);
      return null;
    }

    // Wait for approval (polling for callback_query from inline buttons)
    const approval = await pollTelegramApproval(
      mfaConfig,
      sendResult.messageId,
      sendResult.requestId,
      secretPath,
    );

    if (!approval.approved) {
      console.error(`[secrets:ganesh] MFA denied: ${approval.error}`);
      return null;
    }

    console.log(`[secrets:ganesh] Tier 3 access approved for: ${secretPath}`);

    // Return the secret (never cached for Tier 3)
    return this.secretsCache.get(secretPath) ?? null;
  }

  async store(secretPath: string, value: string): Promise<boolean> {
    // Auto-unlock if needed
    if (!this.unlocked) {
      const ok = await this.unlock();
      if (!ok) return false;
    }

    try {
      this.secretsCache.set(secretPath, value);
      await this.saveSecrets();

      // Update manifest to track the secret in default group
      await this.updateManifest(secretPath);

      return true;
    } catch (error) {
      console.error("[secrets:ganesh] Failed to store secret:", error);
      return false;
    }
  }

  private async updateManifest(secretId: string): Promise<void> {
    const manifestPath = path.join(this.vaultPath, "manifest.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

    // Find or create default group
    let defaultGroup = manifest.groups.find((g: any) => g.id === "default");
    if (!defaultGroup) {
      defaultGroup = { id: "default", name: "Default", tier: 1, secrets: [] };
      manifest.groups.push(defaultGroup);
    }

    // Add secret to group if not already there
    if (!defaultGroup.secrets.includes(secretId)) {
      defaultGroup.secrets.push(secretId);
    }

    manifest.lastModified = new Date().toISOString();
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  }

  async list(prefix?: string): Promise<string[]> {
    // Auto-unlock if needed
    if (!this.unlocked) {
      const ok = await this.unlock();
      if (!ok) return [];
    }

    const allSecrets = Array.from(this.secretsCache.keys());

    if (prefix) {
      return allSecrets.filter((s) => s.startsWith(prefix));
    }

    return allSecrets;
  }
}
