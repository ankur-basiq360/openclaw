import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  evaluateCommand,
  isPolicyGateEnabled,
  resetPolicyGateCache,
} from "./ganesh-policy-gate.js";

describe("ganesh-policy-gate", () => {
  beforeEach(() => {
    resetPolicyGateCache();
  });

  afterEach(() => {
    resetPolicyGateCache();
  });

  describe("isPolicyGateEnabled", () => {
    it("returns true when policy config file exists", () => {
      // The real machine has the policy file, so this should be true
      const ganeshPolicyPath = path.join(os.homedir(), ".ganesh", "config", "security-policy.json");
      const expected = fs.existsSync(ganeshPolicyPath);
      expect(isPolicyGateEnabled()).toBe(expected);
    });

    it("ignores environment variables (security hardening)", () => {
      // Env vars should NOT affect the policy gate — it's config-file-only
      const before = isPolicyGateEnabled();
      process.env.GANESH_POLICY_GATE = "off";
      expect(isPolicyGateEnabled()).toBe(before);
      process.env.GANESH_POLICY_GATE = "on";
      expect(isPolicyGateEnabled()).toBe(before);
      delete process.env.GANESH_POLICY_GATE;
    });
  });
});

describe("ganesh-policy-gate rule evaluation", () => {
  const ganeshConfigDir = path.join(os.homedir(), ".ganesh", "config");
  const ganeshPolicyPath = path.join(ganeshConfigDir, "security-policy.json");
  let originalPolicy: string | null = null;

  beforeEach(() => {
    resetPolicyGateCache();
    try {
      originalPolicy = fs.readFileSync(ganeshPolicyPath, "utf-8");
    } catch {
      originalPolicy = null;
    }
  });

  afterEach(() => {
    resetPolicyGateCache();
    if (originalPolicy !== null) {
      fs.writeFileSync(ganeshPolicyPath, originalPolicy);
    } else {
      try {
        fs.unlinkSync(ganeshPolicyPath);
      } catch {
        // ignore
      }
    }
  });

  function writePolicyFile(policy: Record<string, unknown>): void {
    fs.mkdirSync(ganeshConfigDir, { recursive: true });
    fs.writeFileSync(ganeshPolicyPath, JSON.stringify(policy));
  }

  it("denies commands matching a deny rule", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "allow",
      rules: [
        {
          id: "block-rm-rf",
          subject: "command",
          conditions: [{ field: "command", op: "contains", value: "rm -rf /" }],
          action: "deny",
          description: "Block recursive root deletion",
          enabled: true,
          priority: 100,
        },
      ],
    });

    const result = await evaluateCommand("rm -rf /");
    expect(result.decision).toBe("deny");
  });

  it("allows commands matching an allow rule", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "deny",
      rules: [
        {
          id: "allow-ls",
          subject: "command",
          conditions: [{ field: "baseCommand", op: "eq", value: "ls" }],
          action: "allow",
          description: "Allow ls",
          enabled: true,
        },
      ],
    });

    const result = await evaluateCommand("ls -la /tmp");
    expect(result.decision).toBe("allow");
  });

  it("returns ask for commands matching an ask rule", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "allow",
      rules: [
        {
          id: "ask-docker",
          subject: "command",
          conditions: [{ field: "baseCommand", op: "eq", value: "docker" }],
          action: "ask",
          description: "Require approval for docker",
          enabled: true,
        },
      ],
    });

    const result = await evaluateCommand("docker run ubuntu");
    expect(result.decision).toBe("ask");
  });

  it("uses default action when no rules match", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "ask",
      rules: [],
    });

    const result = await evaluateCommand("some-random-command");
    expect(result.decision).toBe("ask");
    expect(result.reason).toContain("default policy");
  });

  it("skips disabled rules", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "allow",
      rules: [
        {
          id: "disabled-deny",
          subject: "command",
          conditions: [{ field: "baseCommand", op: "eq", value: "ls" }],
          action: "deny",
          enabled: false,
        },
      ],
    });

    const result = await evaluateCommand("ls");
    expect(result.decision).toBe("allow");
  });

  it("evaluates rules by priority (highest first)", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "deny",
      rules: [
        {
          id: "low-priority-deny",
          subject: "command",
          conditions: [{ field: "baseCommand", op: "eq", value: "git" }],
          action: "deny",
          priority: 1,
          enabled: true,
        },
        {
          id: "high-priority-allow",
          subject: "command",
          conditions: [{ field: "baseCommand", op: "eq", value: "git" }],
          action: "allow",
          priority: 10,
          enabled: true,
        },
      ],
    });

    const result = await evaluateCommand("git status");
    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("high-priority-allow");
  });

  it("handles sudo prefix in command extraction", async () => {
    writePolicyFile({
      version: 1,
      defaultAction: "allow",
      rules: [
        {
          id: "deny-systemctl",
          subject: "command",
          conditions: [{ field: "baseCommand", op: "eq", value: "systemctl" }],
          action: "deny",
          enabled: true,
        },
      ],
    });

    const result = await evaluateCommand("sudo systemctl stop openclaw");
    expect(result.decision).toBe("deny");
  });
});
