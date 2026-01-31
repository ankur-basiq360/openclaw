/**
 * Ganesh Backend Tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import { GaneshBackend } from "./ganesh.js";

describe("GaneshBackend", () => {
  let tempDir: string;
  let backend: GaneshBackend;

  // Helper to check if age is available
  const isAgeAvailable = (): boolean => {
    try {
      execSync("which age", { stdio: "ignore" });
      execSync("which age-keygen", { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  };

  beforeAll(async () => {
    if (!isAgeAvailable()) {
      console.log("Skipping Ganesh backend tests: age not installed");
      return;
    }

    // Create temp vault directory
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ganesh-test-"));

    // Generate identity
    const identity = execSync("age-keygen", { encoding: "utf-8" });
    const secretKeyMatch = identity.match(/AGE-SECRET-KEY-\S+/);
    const publicKeyMatch = identity.match(/age1\S+/);

    if (!secretKeyMatch || !publicKeyMatch) {
      throw new Error("Failed to generate age identity");
    }

    const secretKey = secretKeyMatch[0];
    const publicKey = publicKeyMatch[0];

    // Create manifest
    const manifest = {
      version: 1,
      created: new Date().toISOString(),
      lastModified: new Date().toISOString(),
      groups: [{ id: "default", name: "Default", tier: 1, secrets: [] }],
      defaultTier: 1,
    };

    fs.writeFileSync(path.join(tempDir, "manifest.json"), JSON.stringify(manifest, null, 2), {
      mode: 0o600,
    });

    // Create identity file
    fs.writeFileSync(path.join(tempDir, "identity.key"), secretKey, {
      mode: 0o600,
    });

    // Create empty encrypted secrets
    const emptySecrets = JSON.stringify({ secrets: {} });
    execSync(
      `echo '${emptySecrets}' | age -r "${publicKey}" -o "${path.join(tempDir, "secrets.age")}"`,
    );

    backend = new GaneshBackend({ vaultPath: tempDir });
  });

  afterAll(() => {
    if (tempDir) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("detects availability when vault exists", async () => {
    if (!isAgeAvailable()) return;
    const available = await backend.isAvailable();
    expect(available).toBe(true);
  });

  it("detects unavailability when vault missing", async () => {
    const missingBackend = new GaneshBackend({ vaultPath: "/nonexistent/path" });
    const available = await missingBackend.isAvailable();
    expect(available).toBe(false);
  });

  it("unlocks and locks vault", async () => {
    if (!isAgeAvailable()) return;

    const unlocked = await backend.unlock();
    expect(unlocked).toBe(true);

    backend.lock();
    // After lock, cache should be cleared
  });

  it("stores and retrieves secrets", async () => {
    if (!isAgeAvailable()) return;

    // Store a secret
    const stored = await backend.store("test/api-key", "sk-test-123");
    expect(stored).toBe(true);

    // Retrieve it
    const value = await backend.resolve("test/api-key");
    expect(value).toBe("sk-test-123");
  });

  it("lists secrets", async () => {
    if (!isAgeAvailable()) return;

    // Store another secret
    await backend.store("test/another", "value-456");

    const all = await backend.list();
    expect(all).toContain("test/api-key");
    expect(all).toContain("test/another");

    // List with prefix
    const testOnly = await backend.list("test/");
    expect(testOnly.length).toBe(2);
  });

  it("returns null for missing secrets", async () => {
    if (!isAgeAvailable()) return;

    const value = await backend.resolve("nonexistent/secret");
    expect(value).toBeNull();
  });
});
