/**
 * Ganesh Policy Gate for OpenClaw Exec Tool
 *
 * Pre-execution policy check that evaluates commands against the ganesh
 * security policy before allowing execution. Integrates with the ganesh
 * policy engine config and audit system.
 *
 * Design principles:
 * - Fail-open: on any error, allow + log warning (never brick the system)
 * - Configurable: can be enabled/disabled via env or config
 * - Auditable: all decisions logged to ~/.ganesh/audit/
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { logInfo, logWarn } from "../logger.js";

// ============================================================================
// Types
// ============================================================================

export type PolicyGateDecision = "allow" | "deny" | "ask";

export interface PolicyGateResult {
  decision: PolicyGateDecision;
  reason: string;
  matchedRule?: string;
  evaluatedAt: string;
}

interface PolicyCondition {
  field: string;
  op: "eq" | "neq" | "contains" | "matches" | "in" | "gt" | "lt";
  value: string | number | string[];
}

interface PolicyRule {
  id: string;
  description?: string;
  subject: string;
  conditions: PolicyCondition[];
  action: string;
  requiredTier?: number;
  priority?: number;
  enabled?: boolean;
}

interface PolicyConfig {
  version: number;
  name?: string;
  defaultAction: string;
  defaultTier?: number;
  rules: PolicyRule[];
}

interface AuditEntry {
  timestamp: string;
  event: "policy_gate_check";
  command: string;
  decision: PolicyGateDecision;
  reason: string;
  matchedRule?: string;
  agentId?: string;
  sessionKey?: string;
  host?: string;
}

// ============================================================================
// Configuration
// ============================================================================

const GANESH_HOME = path.join(os.homedir(), ".ganesh");
const POLICY_PATH = path.join(GANESH_HOME, "config", "security-policy.json");
const AUDIT_DIR = path.join(GANESH_HOME, "audit");

/** Check if the policy gate is enabled */
export function isPolicyGateEnabled(): boolean {
  // Env override takes precedence
  const envVal = process.env.GANESH_POLICY_GATE?.toLowerCase();
  if (envVal === "0" || envVal === "false" || envVal === "off") {
    return false;
  }
  if (envVal === "1" || envVal === "true" || envVal === "on") {
    return true;
  }
  // Default: enabled if policy config exists
  return fs.existsSync(POLICY_PATH);
}

// ============================================================================
// Policy Loading (cached with TTL)
// ============================================================================

let cachedPolicy: PolicyConfig | null = null;
let cachedPolicyMtime: number = 0;
let lastPolicyCheck: number = 0;
const POLICY_CACHE_TTL_MS = 30_000; // re-check file every 30s

function loadPolicy(): PolicyConfig | null {
  const now = Date.now();

  // Use cache if fresh
  if (cachedPolicy && now - lastPolicyCheck < POLICY_CACHE_TTL_MS) {
    return cachedPolicy;
  }
  lastPolicyCheck = now;

  try {
    if (!fs.existsSync(POLICY_PATH)) {
      return null;
    }
    const stat = fs.statSync(POLICY_PATH);
    if (cachedPolicy && stat.mtimeMs === cachedPolicyMtime) {
      return cachedPolicy;
    }

    const data = fs.readFileSync(POLICY_PATH, "utf-8");
    cachedPolicy = JSON.parse(data) as PolicyConfig;
    cachedPolicyMtime = stat.mtimeMs;
    return cachedPolicy;
  } catch (err) {
    logWarn(`ganesh-policy-gate: failed to load policy: ${err}`);
    return null;
  }
}

// ============================================================================
// Condition Evaluation
// ============================================================================

function getNestedValue(obj: Record<string, unknown>, fieldPath: string): unknown {
  const parts = fieldPath.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object") {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function evaluateCondition(condition: PolicyCondition, details: Record<string, unknown>): boolean {
  const value = getNestedValue(details, condition.field);

  switch (condition.op) {
    case "eq":
      return value === condition.value;
    case "neq":
      return value !== condition.value;
    case "contains":
      if (typeof value === "string" && typeof condition.value === "string") {
        return value.includes(condition.value);
      }
      if (Array.isArray(value)) {
        return value.includes(condition.value);
      }
      return false;
    case "matches":
      if (typeof value === "string" && typeof condition.value === "string") {
        try {
          return new RegExp(condition.value).test(value);
        } catch {
          return false;
        }
      }
      return false;
    case "in":
      return Array.isArray(condition.value) && condition.value.includes(value as string);
    case "gt":
      return (
        typeof value === "number" && typeof condition.value === "number" && value > condition.value
      );
    case "lt":
      return (
        typeof value === "number" && typeof condition.value === "number" && value < condition.value
      );
    default:
      return false;
  }
}

// ============================================================================
// Core: Evaluate Command Against Policy
// ============================================================================

/**
 * Evaluate a command against the ganesh security policy.
 *
 * @param command - The shell command string
 * @param opts - Optional context (agentId, sessionKey, host, cwd)
 * @returns PolicyGateResult with decision and reason
 */
export function evaluateCommand(
  command: string,
  opts?: {
    agentId?: string;
    sessionKey?: string;
    host?: string;
    cwd?: string;
  },
): PolicyGateResult {
  const now = new Date().toISOString();

  // If policy gate is disabled, always allow
  if (!isPolicyGateEnabled()) {
    return { decision: "allow", reason: "Policy gate disabled", evaluatedAt: now };
  }

  let policy: PolicyConfig | null;
  try {
    policy = loadPolicy();
  } catch (err) {
    // Fail-open
    logWarn(`ganesh-policy-gate: error loading policy, failing open: ${err}`);
    writeAudit({
      timestamp: now,
      event: "policy_gate_check",
      command,
      decision: "allow",
      reason: `Fail-open: policy load error: ${err}`,
      agentId: opts?.agentId,
      sessionKey: opts?.sessionKey,
      host: opts?.host,
    });
    return { decision: "allow", reason: "Fail-open: policy load error", evaluatedAt: now };
  }

  if (!policy) {
    return { decision: "allow", reason: "No policy config found", evaluatedAt: now };
  }

  // Extract the base command name for matching
  const baseCommand = extractBaseCommand(command);

  // Build details object for condition matching
  const details: Record<string, unknown> = {
    command,
    baseCommand,
    name: baseCommand,
    host: opts?.host,
    cwd: opts?.cwd,
    agentId: opts?.agentId,
  };

  // Get rules for "command" subject, sorted by priority desc
  const commandRules = (policy.rules || [])
    .filter((r) => r.subject === "command" && r.enabled !== false)
    .toSorted((a, b) => (b.priority || 0) - (a.priority || 0));

  // Evaluate rules
  for (const rule of commandRules) {
    const allMatch = rule.conditions.every((c) => evaluateCondition(c, details));
    if (allMatch) {
      const action = normalizeAction(rule.action);
      const result: PolicyGateResult = {
        decision: action,
        reason: rule.description || `Matched rule: ${rule.id}`,
        matchedRule: rule.id,
        evaluatedAt: now,
      };

      writeAudit({
        timestamp: now,
        event: "policy_gate_check",
        command,
        decision: action,
        reason: result.reason,
        matchedRule: rule.id,
        agentId: opts?.agentId,
        sessionKey: opts?.sessionKey,
        host: opts?.host,
      });

      logInfo(`ganesh-policy-gate: ${action} "${truncate(command, 80)}" (rule: ${rule.id})`);
      return result;
    }
  }

  // No rule matched - use default action
  const defaultAction = normalizeAction(policy.defaultAction || "ask");
  const result: PolicyGateResult = {
    decision: defaultAction,
    reason: "No matching rule, using default policy",
    evaluatedAt: now,
  };

  writeAudit({
    timestamp: now,
    event: "policy_gate_check",
    command,
    decision: defaultAction,
    reason: result.reason,
    agentId: opts?.agentId,
    sessionKey: opts?.sessionKey,
    host: opts?.host,
  });

  logInfo(`ganesh-policy-gate: ${defaultAction} "${truncate(command, 80)}" (default policy)`);
  return result;
}

// ============================================================================
// Helpers
// ============================================================================

function normalizeAction(action: string): PolicyGateDecision {
  const lower = action.toLowerCase();
  if (lower === "allow") {
    return "allow";
  }
  if (lower === "deny") {
    return "deny";
  }
  // "ask", "mfa", or unknown → "ask"
  return "ask";
}

function extractBaseCommand(command: string): string {
  // Strip leading env vars, sudo, etc.
  const trimmed = command.trim();
  // Remove leading VAR=val assignments
  const withoutEnv = trimmed.replace(/^(\w+=\S+\s+)+/, "");
  // Remove sudo prefix
  const withoutSudo = withoutEnv.replace(/^sudo\s+(-\S+\s+)*/, "");
  // Get first word (the command)
  const match = withoutSudo.match(/^(\S+)/);
  if (!match) {
    return trimmed;
  }
  // Strip path
  return path.basename(match[1]);
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) {
    return str;
  }
  return str.slice(0, maxLen - 3) + "...";
}

// ============================================================================
// Audit Logging
// ============================================================================

let auditDirChecked = false;

function ensureAuditDir(): boolean {
  if (auditDirChecked) {
    return true;
  }
  try {
    if (!fs.existsSync(AUDIT_DIR)) {
      fs.mkdirSync(AUDIT_DIR, { recursive: true, mode: 0o700 });
    }
    auditDirChecked = true;
    return true;
  } catch (err) {
    logWarn(`ganesh-policy-gate: cannot create audit dir: ${err}`);
    return false;
  }
}

function writeAudit(entry: AuditEntry): void {
  try {
    if (!ensureAuditDir()) {
      return;
    }
    const date = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const auditFile = path.join(AUDIT_DIR, `policy-gate-${date}.jsonl`);
    fs.appendFileSync(auditFile, JSON.stringify(entry) + "\n", { mode: 0o600 });
  } catch (err) {
    // Never let audit failures block execution
    logWarn(`ganesh-policy-gate: audit write failed: ${err}`);
  }
}

// ============================================================================
// Reset (for testing)
// ============================================================================

export function resetPolicyGateCache(): void {
  cachedPolicy = null;
  cachedPolicyMtime = 0;
  lastPolicyCheck = 0;
  auditDirChecked = false;
}
