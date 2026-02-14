import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  evaluateCommand,
  isPolicyGateEnabled,
  resetPolicyGateCache,
} from "./ganesh-policy-gate.js";

// Tests use the real ~/.ganesh paths for integration testing

describe("ganesh-policy-gate", () => {
  beforeEach(() => {
    resetPolicyGateCache();
  });

  afterEach(() => {
    delete process.env.GANESH_POLICY_GATE;
    resetPolicyGateCache();
  });

  describe("isPolicyGateEnabled", () => {
    it("returns false when env is set to off", () => {
      process.env.GANESH_POLICY_GATE = "off";
      expect(isPolicyGateEnabled()).toBe(false);
    });

    it("returns false when env is set to false", () => {
      process.env.GANESH_POLICY_GATE = "false";
      expect(isPolicyGateEnabled()).toBe(false);
    });

    it("returns true when env is set to on", () => {
      process.env.GANESH_POLICY_GATE = "on";
      expect(isPolicyGateEnabled()).toBe(true);
    });
  });

  describe("evaluateCommand", () => {
    it("returns allow when policy gate is disabled", () => {
      process.env.GANESH_POLICY_GATE = "off";
      const result = evaluateCommand("rm -rf /");
      expect(result.decision).toBe("allow");
      expect(result.reason).toContain("disabled");
    });

    it("returns allow when no policy config exists", () => {
      process.env.GANESH_POLICY_GATE = "on";
      // No policy file exists at default path - loadPolicy returns null
      const result = evaluateCommand("ls");
      expect(result.decision).toBe("allow");
    });
  });

  describe("extractBaseCommand (tested via evaluateCommand)", () => {
    // We test command extraction indirectly through rule matching
    it("handles simple commands", () => {
      process.env.GANESH_POLICY_GATE = "off";
      const result = evaluateCommand("git status");
      expect(result.decision).toBe("allow");
    });
  });
});

describe("ganesh-policy-gate rule evaluation", () => {
  // These tests need to write policy to the actual ganesh path
  // We'll use the env var approach and test the evaluateCommand logic
  // with the real policy path. Skip if we can't write there.

  const ganeshConfigDir = path.join(os.homedir(), ".ganesh", "config");
  const ganeshPolicyPath = path.join(ganeshConfigDir, "security-policy.json");
  let originalPolicy: string | null = null;

  beforeEach(() => {
    resetPolicyGateCache();
    // Back up existing policy
    try {
      originalPolicy = fs.readFileSync(ganeshPolicyPath, "utf-8");
    } catch {
      originalPolicy = null;
    }
  });

  afterEach(() => {
    delete process.env.GANESH_POLICY_GATE;
    resetPolicyGateCache();
    // Restore original policy
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

  it("denies commands matching a deny rule", () => {
    process.env.GANESH_POLICY_GATE = "on";
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

    const result = evaluateCommand("rm -rf /");
    expect(result.decision).toBe("deny");
    expect(result.matchedRule).toBe("block-rm-rf");
  });

  it("allows commands matching an allow rule", () => {
    process.env.GANESH_POLICY_GATE = "on";
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

    const result = evaluateCommand("ls -la /tmp");
    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("allow-ls");
  });

  it("returns ask for commands matching an ask rule", () => {
    process.env.GANESH_POLICY_GATE = "on";
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

    const result = evaluateCommand("docker run ubuntu");
    expect(result.decision).toBe("ask");
    expect(result.matchedRule).toBe("ask-docker");
  });

  it("uses default action when no rules match", () => {
    process.env.GANESH_POLICY_GATE = "on";
    writePolicyFile({
      version: 1,
      defaultAction: "ask",
      rules: [],
    });

    const result = evaluateCommand("some-random-command");
    expect(result.decision).toBe("ask");
    expect(result.reason).toContain("default policy");
  });

  it("skips disabled rules", () => {
    process.env.GANESH_POLICY_GATE = "on";
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

    const result = evaluateCommand("ls");
    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBeUndefined();
  });

  it("evaluates rules by priority (highest first)", () => {
    process.env.GANESH_POLICY_GATE = "on";
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

    const result = evaluateCommand("git status");
    expect(result.decision).toBe("allow");
    expect(result.matchedRule).toBe("high-priority-allow");
  });

  it("supports regex matching", () => {
    process.env.GANESH_POLICY_GATE = "on";
    writePolicyFile({
      version: 1,
      defaultAction: "allow",
      rules: [
        {
          id: "deny-curl-sensitive",
          subject: "command",
          conditions: [{ field: "command", op: "matches", value: "curl.*\\.(bank|secret)\\.com" }],
          action: "deny",
          enabled: true,
        },
      ],
    });

    expect(evaluateCommand("curl https://api.bank.com/transfer").decision).toBe("deny");
    expect(evaluateCommand("curl https://example.com").decision).toBe("allow");
  });

  it("handles sudo prefix in command extraction", () => {
    process.env.GANESH_POLICY_GATE = "on";
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

    const result = evaluateCommand("sudo systemctl stop openclaw");
    expect(result.decision).toBe("deny");
  });

  it("writes audit log entries", () => {
    process.env.GANESH_POLICY_GATE = "on";
    writePolicyFile({
      version: 1,
      defaultAction: "allow",
      rules: [],
    });

    evaluateCommand("echo hello", { agentId: "test-agent" });

    const auditDir = path.join(os.homedir(), ".ganesh", "audit");
    const date = new Date().toISOString().slice(0, 10);
    const auditFile = path.join(auditDir, `policy-gate-${date}.jsonl`);

    expect(fs.existsSync(auditFile)).toBe(true);
    const lines = fs.readFileSync(auditFile, "utf-8").trim().split("\n");
    const lastEntry = JSON.parse(lines[lines.length - 1]);
    expect(lastEntry.event).toBe("policy_gate_check");
    expect(lastEntry.command).toBe("echo hello");
    expect(lastEntry.agentId).toBe("test-agent");
  });
});
