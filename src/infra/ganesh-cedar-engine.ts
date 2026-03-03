/**
 * Ganesh Cedar Policy Engine
 *
 * Replaces the custom JSON policy evaluator with AWS Cedar (via WASM).
 * Cedar provides formal verification, standard policy language, and
 * richer ABAC/RBAC support.
 *
 * Design principles:
 * - Fail-open: on any error, allow + log warning (never brick the system)
 * - File-watched: schema + policies reload on change (no restart needed)
 * - Auditable: all decisions logged to ~/.ganesh/audit/
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { logInfo, logWarn } from "../logger.js";
import type { PolicyGateDecision, PolicyGateResult } from "./ganesh-policy-gate.js";

// ============================================================================
// Configuration
// ============================================================================

const GANESH_HOME = path.join(os.homedir(), ".ganesh");
const CEDAR_DIR = path.join(GANESH_HOME, "config", "cedar");
const SCHEMA_PATH = path.join(CEDAR_DIR, "schema.cedarschema");
const POLICIES_PATH = path.join(CEDAR_DIR, "policies.cedar");
const POLICIES_D_DIR = path.join(CEDAR_DIR, "policies.d");
const AUDIT_DIR = path.join(GANESH_HOME, "audit");

// Cedar WASM module (lazy loaded)
let cedarModule: CedarWasm | null = null;
let cedarLoadError: string | null = null;

// Cached policy/schema with mtime tracking
let cachedPolicies: Record<string, string> | null = null;
let cachedPoliciesRaw: string | null = null;
let cachedSchema: string | null = null;
let policiesMtime: number = 0;
let schemaMtime: number = 0;
let lastFileCheck: number = 0;
const FILE_CHECK_TTL_MS = 10_000;

// ============================================================================
// Types
// ============================================================================

interface CedarWasm {
  isAuthorized: (request: Record<string, unknown>) => {
    type: string;
    response: {
      decision: string;
      diagnostics: { reason: string[]; errors: Array<{ policyId: string; error: string }> };
    };
  };
  checkParsePolicySet: (
    policies: unknown,
    schema?: unknown,
  ) => { success: boolean; errors?: string[] };
  checkParseSchema: (schema: string) => { success: boolean; errors?: string[] };
  getCedarVersion: () => string;
}

// Cedar WASM types (minimal — matches the subset of the WASM API we use).

interface AuditEntry {
  timestamp: string;
  event: "cedar_policy_check";
  command: string;
  decision: PolicyGateDecision;
  reason: string;
  cedarDecision?: string;
  determinedPolicies?: string[];
  errors?: string[];
  agentId?: string;
  sessionKey?: string;
  host?: string;
}

// Policies with "ask-" prefix map to "ask" decision instead of hard deny.
// This is detected dynamically from the policy ID naming convention.

// ============================================================================
// Cedar Module Loading
// ============================================================================

async function loadCedarModule(): Promise<CedarWasm | null> {
  if (cedarModule) {
    return cedarModule;
  }
  if (cedarLoadError) {
    return null;
  }

  try {
    // Dynamic import of the ESM cedar-wasm/nodejs
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mod: any = await import("@cedar-policy/cedar-wasm/nodejs");
    cedarModule = mod.default || mod;
    logInfo(`ganesh-cedar: loaded Cedar ${cedarModule!.getCedarVersion()}`);
    return cedarModule;
  } catch (err) {
    cedarLoadError = String(err);
    logWarn(`ganesh-cedar: failed to load Cedar WASM: ${cedarLoadError}`);
    return null;
  }
}

// ============================================================================
// Policy/Schema File Loading
// ============================================================================

function reloadFilesIfNeeded(): { policies: Record<string, string> | null; schema: string | null } {
  const now = Date.now();
  if (cachedPolicies && now - lastFileCheck < FILE_CHECK_TTL_MS) {
    return { policies: cachedPolicies, schema: cachedSchema };
  }
  lastFileCheck = now;

  try {
    if (!fs.existsSync(POLICIES_PATH)) {
      return { policies: null, schema: null };
    }

    const pStat = fs.statSync(POLICIES_PATH);
    // Also check policies.d/ directory mtime
    let policiesDMtime = 0;
    if (fs.existsSync(POLICIES_D_DIR)) {
      policiesDMtime = fs.statSync(POLICIES_D_DIR).mtimeMs;
    }
    // Use string concat of mtimes to avoid numeric collision
    const combinedMtime = pStat.mtimeMs * 1000 + policiesDMtime;

    if (combinedMtime !== policiesMtime) {
      // Load main policy file
      let raw = fs.readFileSync(POLICIES_PATH, "utf-8");

      // Load additional policies from policies.d/
      if (fs.existsSync(POLICIES_D_DIR)) {
        const extraFiles = fs
          .readdirSync(POLICIES_D_DIR)
          .filter((f) => f.endsWith(".cedar"))
          .toSorted();
        for (const file of extraFiles) {
          const extraPath = path.join(POLICIES_D_DIR, file);
          raw += "\n\n// ── from policies.d/" + file + " ──\n";
          raw += fs.readFileSync(extraPath, "utf-8");
        }
      }

      cachedPoliciesRaw = raw;
      // Parse into named policies using @id annotations
      cachedPolicies = parsePoliciesIntoMap(raw);
      policiesMtime = combinedMtime;
      logInfo(`ganesh-cedar: policies reloaded (${Object.keys(cachedPolicies).length} rules)`);
    }

    if (fs.existsSync(SCHEMA_PATH)) {
      const sStat = fs.statSync(SCHEMA_PATH);
      if (sStat.mtimeMs !== schemaMtime) {
        cachedSchema = fs.readFileSync(SCHEMA_PATH, "utf-8");
        schemaMtime = sStat.mtimeMs;
        logInfo("ganesh-cedar: schema reloaded");
      }
    }
  } catch (err) {
    logWarn(`ganesh-cedar: file reload error: ${String(err)}`);
  }

  return { policies: cachedPolicies, schema: cachedSchema };
}

/**
 * Parse Cedar policy text into a named map using @id annotations.
 * Cedar's isAuthorized returns policy IDs in diagnostics.reason when
 * policies are provided as Record<PolicyId, Policy>.
 */
function parsePoliciesIntoMap(policyText: string): Record<string, string> {
  const result: Record<string, string> = {};
  // Split on @id annotations — each policy starts with @id("...")
  const policyRegex = /@id\("([^"]+)"\)\s*((?:permit|forbid)\s*\([\s\S]*?;)/g;
  let match;
  while ((match = policyRegex.exec(policyText)) !== null) {
    const id = match[1];
    const fullPolicy = `@id("${id}")\n${match[2]}`;
    result[id] = fullPolicy;
  }
  return result;
}

// ============================================================================
// Check if Cedar engine is available
// ============================================================================

export function isCedarAvailable(): boolean {
  return fs.existsSync(POLICIES_PATH);
}

// ============================================================================
// Core: Evaluate Command via Cedar
// ============================================================================

export async function evaluateCommandCedar(
  command: string,
  opts?: {
    agentId?: string;
    sessionKey?: string;
    host?: string;
    cwd?: string;
  },
): Promise<PolicyGateResult> {
  const now = new Date().toISOString();

  // Load Cedar WASM
  const cedar = await loadCedarModule();
  if (!cedar) {
    // Fail-open
    writeAudit({
      timestamp: now,
      event: "cedar_policy_check",
      command,
      decision: "allow",
      reason: "Fail-open: Cedar WASM not available",
      agentId: opts?.agentId,
      sessionKey: opts?.sessionKey,
      host: opts?.host,
    });
    return { decision: "allow", reason: "Fail-open: Cedar WASM not available", evaluatedAt: now };
  }

  // Load policies
  const { policies, schema: _schema } = reloadFilesIfNeeded();
  if (!policies) {
    return { decision: "allow", reason: "No Cedar policies found", evaluatedAt: now };
  }

  // Build Cedar entities and request
  const baseCommand = extractBaseCommand(command);
  const agentId = opts?.agentId || "main";
  const sessionKey = opts?.sessionKey || "unknown";
  const commandId = `cmd-${Date.now()}`;
  const sessionTier = classifySessionTier(agentId, sessionKey);

  // Agent parents determine role-based permissions
  const agentParents: Array<{ type: string; id: string }> = [];
  agentParents.push({ type: "Ganesh::Role", id: sessionTier.role });

  const entities = [
    // Role entities (empty, just for grouping)
    { uid: { type: "Ganesh::Role", id: "admin" }, attrs: {}, parents: [] },
    { uid: { type: "Ganesh::Role", id: "worker" }, attrs: {}, parents: [] },
    { uid: { type: "Ganesh::Role", id: "restricted" }, attrs: {}, parents: [] },
    {
      uid: { type: "Ganesh::Agent", id: agentId },
      attrs: {
        tier: sessionTier.tier,
        session: sessionKey,
        sessionType: sessionTier.type,
      },
      parents: agentParents,
    },
    {
      uid: { type: "Ganesh::Command", id: commandId },
      attrs: {
        raw: command,
        base: baseCommand,
        args: command.replace(/^\S+\s*/, ""),
      },
      parents: [],
    },
  ];

  const context: Record<string, unknown> = {
    cwd: opts?.cwd || process.cwd(),
    host: opts?.host || os.hostname(),
    time: now,
    hasSudo: command.trimStart().startsWith("sudo"),
  };

  try {
    const result = cedar.isAuthorized({
      principal: { type: "Ganesh::Agent", id: agentId },
      action: { type: "Ganesh::Action", id: "exec" },
      resource: { type: "Ganesh::Command", id: commandId },
      context,
      policies: { staticPolicies: policies },
      entities,
    });

    if (result.type !== "success") {
      // Fail-open on unexpected response
      logWarn(`ganesh-cedar: unexpected response type: ${JSON.stringify(result)}`);
      writeAudit({
        timestamp: now,
        event: "cedar_policy_check",
        command,
        decision: "allow",
        reason: `Fail-open: unexpected Cedar response`,
        agentId: opts?.agentId,
        sessionKey: opts?.sessionKey,
        host: opts?.host,
      });
      return {
        decision: "allow",
        reason: "Fail-open: unexpected Cedar response",
        evaluatedAt: now,
      };
    }

    const cedarDecision = result.response.decision;
    const reasons = result.response.diagnostics.reason || [];
    const errors = result.response.diagnostics.errors || [];

    // Map Cedar decision to our gate decision
    let decision: PolicyGateDecision;
    let matchedRule: string | undefined;

    if (cedarDecision === "allow") {
      decision = "allow";
      matchedRule = reasons[0];
    } else {
      // Cedar denied — check if the forbid policy is an "ask" policy
      const isAskPolicy = reasons.some((r) => r.startsWith("ask-"));
      decision = isAskPolicy ? "ask" : "deny";
      matchedRule = reasons[0];
    }

    const reasonText =
      reasons.length > 0
        ? `Cedar ${cedarDecision}: ${reasons.join(", ")}`
        : `Cedar ${cedarDecision} (default)`;

    writeAudit({
      timestamp: now,
      event: "cedar_policy_check",
      command,
      decision,
      reason: reasonText,
      cedarDecision,
      determinedPolicies: reasons,
      errors: errors.map((e) => `${e.policyId}: ${e.error}`),
      agentId: opts?.agentId,
      sessionKey: opts?.sessionKey,
      host: opts?.host,
    });

    logInfo(
      `ganesh-cedar: ${decision} "${truncate(command, 80)}" (cedar: ${cedarDecision}, policies: ${reasons.join(",") || "none"})`,
    );

    return {
      decision,
      reason: reasonText,
      matchedRule,
      evaluatedAt: now,
    };
  } catch (err) {
    // Fail-open
    logWarn(`ganesh-cedar: evaluation error: ${String(err)}`);
    writeAudit({
      timestamp: now,
      event: "cedar_policy_check",
      command,
      decision: "allow",
      reason: `Fail-open: Cedar evaluation error: ${String(err)}`,
      agentId: opts?.agentId,
      sessionKey: opts?.sessionKey,
      host: opts?.host,
    });
    return {
      decision: "allow",
      reason: `Fail-open: Cedar evaluation error`,
      evaluatedAt: now,
    };
  }
}

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// Session Tier Classification
// ============================================================================

interface SessionTier {
  tier: number; // 1=admin, 2=worker, 3=restricted
  role: string; // Cedar role entity ID
  type: string; // session type for logging
}

/**
 * Classify a session into a permission tier based on agent ID and session key.
 *
 * Tier 1 (admin): Main session — direct chat with Ankur. Full access.
 * Tier 2 (worker): Cron jobs and spawned sub-agents from main. Most commands allowed,
 *                  but no service start/restart, no sensitive file access.
 * Tier 3 (restricted): Unknown or external agents. Minimal permissions.
 */
function classifySessionTier(agentId: string, sessionKey: string): SessionTier {
  // Main session: direct conversation
  if (agentId === "main" && !sessionKey.includes("cron:") && !sessionKey.includes(":spawn:")) {
    return { tier: 1, role: "admin", type: "main" };
  }

  // Cron jobs spawned by main agent
  if (sessionKey.includes("cron:") || sessionKey.startsWith("agent:main:cron:")) {
    return { tier: 2, role: "worker", type: "cron" };
  }

  // Sub-agents spawned by main
  if (agentId === "main" && (sessionKey.includes(":spawn:") || sessionKey.includes("isolated"))) {
    return { tier: 2, role: "worker", type: "sub-agent" };
  }

  // Known agent IDs that we trust
  if (agentId === "main") {
    return { tier: 2, role: "worker", type: "main-derived" };
  }

  // Everything else: restricted
  return { tier: 3, role: "restricted", type: "unknown" };
}

// ============================================================================
// Helpers
// ============================================================================

function extractBaseCommand(command: string): string {
  const trimmed = command.trim();
  const withoutEnv = trimmed.replace(/^(\w+=\S+\s+)+/, "");
  const withoutSudo = withoutEnv.replace(/^sudo\s+(-\S+\s+)*/, "");
  const match = withoutSudo.match(/^(\S+)/);
  if (!match) {
    return trimmed;
  }
  return path.basename(match[1]);
}

function truncate(str: string, maxLen: number): string {
  return str.length <= maxLen ? str : str.slice(0, maxLen - 3) + "...";
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
  } catch {
    return false;
  }
}

function writeAudit(entry: AuditEntry): void {
  try {
    if (!ensureAuditDir()) {
      return;
    }
    const date = new Date().toISOString().slice(0, 10);
    const auditFile = path.join(AUDIT_DIR, `cedar-${date}.jsonl`);
    fs.appendFileSync(auditFile, JSON.stringify(entry) + "\n", { mode: 0o600 });
  } catch (err) {
    logWarn(`ganesh-cedar: audit write failed: ${String(err)}`);
  }
}

// ============================================================================
// Validation helpers (for CLI/testing)
// ============================================================================

// TODO: wire into `ganesh cedar validate` CLI command
export async function validatePolicies(): Promise<{ valid: boolean; errors: string[] }> {
  const cedar = await loadCedarModule();
  if (!cedar) {
    return { valid: false, errors: ["Cedar WASM not available"] };
  }

  const { policies, schema: _schema } = reloadFilesIfNeeded();
  if (!policies) {
    return { valid: false, errors: ["No policies file found"] };
  }

  try {
    const result = cedar.checkParsePolicySet(
      { staticPolicies: cachedPoliciesRaw || (policies as unknown as string) },
      _schema || undefined,
    );
    return { valid: result.success, errors: result.errors || [] };
  } catch (err) {
    return { valid: false, errors: [String(err)] };
  }
}

export async function validateSchema(): Promise<{ valid: boolean; errors: string[] }> {
  const cedar = await loadCedarModule();
  if (!cedar) {
    return { valid: false, errors: ["Cedar WASM not available"] };
  }

  if (!fs.existsSync(SCHEMA_PATH)) {
    return { valid: false, errors: ["No schema file found"] };
  }

  try {
    const schemaText = fs.readFileSync(SCHEMA_PATH, "utf-8");
    const result = cedar.checkParseSchema(schemaText);
    return { valid: result.success, errors: result.errors || [] };
  } catch (err) {
    return { valid: false, errors: [String(err)] };
  }
}

// ============================================================================
// Reset (for testing)
// ============================================================================

export function resetCedarCache(): void {
  cachedPolicies = null;
  cachedPoliciesRaw = null;
  cachedSchema = null;
  policiesMtime = 0;
  schemaMtime = 0;
  lastFileCheck = 0;
  auditDirChecked = false;
}
