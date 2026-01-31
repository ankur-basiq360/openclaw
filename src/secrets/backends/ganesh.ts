/**
 * Ganesh Vault Backend
 *
 * Uses the Ganesh Vault for secure secret storage with tiered access.
 * Integrates with the Ganesh Environment for AI-first secret management.
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

// For now, we use CLI-based access. Later, we'll use direct library import.
// import { Vault } from "ganesh-environment";

export class GaneshBackend implements SecretsBackend {
  readonly name = "ganesh" as const;

  private config: GaneshBackendConfig;
  private vaultPath: string;
  private unlocked: boolean = false;
  private secretKey: string | null = null;
  private publicKey: string | null = null;
  private secretsCache: Map<string, string> = new Map();

  constructor(config: GaneshBackendConfig = {}) {
    this.config = config;
    this.vaultPath = (config.vaultPath || "~/.ganesh/vault").replace("~", os.homedir());
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

    const value = this.secretsCache.get(normalizedPath);
    return value ?? null;
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
