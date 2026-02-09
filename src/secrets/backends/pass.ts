/**
 * Pass (password-store) Backend
 *
 * Uses the standard Unix password manager `pass` to retrieve secrets.
 * Secrets are GPG-encrypted at rest and decrypted on demand.
 *
 * @see https://www.passwordstore.org/
 */

import { exec } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { PassBackendConfig, SecretsBackend } from "../types.js";

const execAsync = promisify(exec);

export class PassBackend implements SecretsBackend {
  readonly name = "pass" as const;

  private config: PassBackendConfig;
  private storePath: string;

  constructor(config: PassBackendConfig = {}) {
    this.config = config;
    this.storePath =
      config.storePath ||
      process.env.PASSWORD_STORE_DIR ||
      path.join(os.homedir(), ".password-store");
  }

  async isAvailable(): Promise<boolean> {
    try {
      // Check if pass is installed
      await execAsync("which pass");

      // Check if store directory exists
      if (!fs.existsSync(this.storePath)) {
        return false;
      }

      // Check if .gpg-id exists (store is initialized)
      const gpgIdPath = path.join(this.storePath, ".gpg-id");
      if (!fs.existsSync(gpgIdPath)) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  async resolve(secretPath: string, _field?: string): Promise<string | null> {
    try {
      const env: Record<string, string> = {
        ...process.env,
        PASSWORD_STORE_DIR: this.storePath,
      };

      if (this.config.gpgPath) {
        env.PASSWORD_STORE_GPG_OPTS = `--gpg ${this.config.gpgPath}`;
      }

      // Sanitize path to prevent command injection
      const sanitizedPath = secretPath.replace(/[^a-zA-Z0-9_\-/]/g, "");
      if (sanitizedPath !== secretPath) {
        console.warn(`[secrets:pass] Path sanitized: "${secretPath}" -> "${sanitizedPath}"`);
      }

      const { stdout } = await execAsync(`pass show "${sanitizedPath}"`, {
        env,
        timeout: 10000, // 10 second timeout
      });

      // Return first line only (pass convention: first line is the secret)
      const value = stdout.split("\n")[0]?.trim();
      return value || null;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("not in the password store")) {
        return null;
      }
      console.error(`[secrets:pass] Failed to resolve "${secretPath}":`, message);
      return null;
    }
  }

  async store(secretPath: string, value: string): Promise<boolean> {
    try {
      const env: Record<string, string> = {
        ...process.env,
        PASSWORD_STORE_DIR: this.storePath,
      };

      // Sanitize path
      const sanitizedPath = secretPath.replace(/[^a-zA-Z0-9_\-/]/g, "");

      // Use echo piped to pass insert -m (multiline mode, no confirmation)
      const { stdout, stderr } = await execAsync(
        `echo "${value.replace(/"/g, '\\"')}" | pass insert -m "${sanitizedPath}"`,
        {
          env,
          timeout: 10000,
        },
      );

      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[secrets:pass] Failed to store "${secretPath}":`, message);
      return false;
    }
  }

  async list(prefix?: string): Promise<string[]> {
    try {
      const env: Record<string, string> = {
        ...process.env,
        PASSWORD_STORE_DIR: this.storePath,
      };

      const cmd = prefix ? `pass ls "${prefix}"` : "pass ls";
      const { stdout } = await execAsync(cmd, { env, timeout: 10000 });

      // Parse pass ls output (tree format)
      const lines = stdout.split("\n");
      const secrets: string[] = [];

      for (const line of lines) {
        // Skip tree formatting characters and extract path
        const match = line.match(/[├└──│\s]*([\w\-/]+)/);
        if (match && match[1] && !match[1].includes("Password Store")) {
          secrets.push(match[1]);
        }
      }

      return secrets;
    } catch {
      return [];
    }
  }
}
