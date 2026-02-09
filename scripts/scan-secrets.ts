#!/usr/bin/env npx ts-node
/**
 * Secret Scanner
 *
 * Scans configuration files for plaintext secrets that should be stored in the vault.
 * Run this before commits or as part of CI to catch exposed credentials.
 *
 * Usage:
 *   npx ts-node scripts/scan-secrets.ts
 *   # or
 *   npm run scan:secrets
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// ============================================================================
// Patterns that indicate plaintext secrets
// ============================================================================

const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
}> = [
  // Anthropic API keys
  { name: "Anthropic API Key", pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/, severity: "critical" },

  // OpenAI API keys
  { name: "OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{48,}/, severity: "critical" },

  // Telegram bot tokens (number:alphanumeric)
  { name: "Telegram Bot Token", pattern: /\d{9,}:[A-Za-z0-9_-]{35}/, severity: "critical" },

  // Google API keys
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z_-]{35}/, severity: "high" },

  // GitHub tokens
  { name: "GitHub Token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/, severity: "critical" },

  // Generic patterns (lower confidence)
  {
    name: "Generic API Key/Secret",
    pattern: /"(api[_-]?key|apikey|secret[_-]?key|secretkey)":\s*"[a-zA-Z0-9_-]{32,}"/i,
    severity: "medium",
  },
];

// Files to scan
const CONFIG_FILES = [
  path.join(os.homedir(), ".openclaw", "openclaw.json"),
  path.join(os.homedir(), ".openclaw", "agents", "main", "agent", "auth-profiles.json"),
];

// Files/patterns to ignore (already using refs)
const IGNORE_PATTERNS = [
  /Ref":\s*"[^"]+"/, // tokenRef, keyRef, botTokenRef - these are refs, not secrets
];

// ============================================================================
// Scanner
// ============================================================================

interface Finding {
  file: string;
  line: number;
  pattern: string;
  match: string;
  severity: "critical" | "high" | "medium";
}

function scanFile(filePath: string): Finding[] {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n");
  const findings: Finding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip lines that are using refs (safe pattern)
    if (IGNORE_PATTERNS.some((p) => p.test(line))) {
      continue;
    }

    for (const { name, pattern, severity } of SECRET_PATTERNS) {
      const match = line.match(pattern);
      if (match) {
        // Redact the match for display
        const redacted =
          match[0].length > 20
            ? match[0].slice(0, 12) + "..." + match[0].slice(-4)
            : match[0].slice(0, 8) + "...";

        findings.push({
          file: filePath,
          line: i + 1,
          pattern: name,
          match: redacted,
          severity,
        });
      }
    }
  }

  return findings;
}

function checkRefUsage(filePath: string): string[] {
  const warnings: string[] = [];

  if (!fs.existsSync(filePath)) {
    return warnings;
  }

  try {
    const content = JSON.parse(fs.readFileSync(filePath, "utf-8"));

    // Check openclaw.json
    if (filePath.endsWith("openclaw.json")) {
      // Telegram should use botTokenRef
      if (content.channels?.telegram?.enabled) {
        if (content.channels.telegram.botToken && !content.channels.telegram.botTokenRef) {
          warnings.push(`${filePath}: Telegram is using plaintext botToken instead of botTokenRef`);
        }
      }
    }

    // Check auth-profiles.json
    if (filePath.endsWith("auth-profiles.json")) {
      for (const [profileId, profile] of Object.entries(content.profiles || {})) {
        const p = profile as Record<string, unknown>;

        if (p.type === "token" && p.token && !p.tokenRef) {
          warnings.push(`${filePath}: Profile "${profileId}" has plaintext token without tokenRef`);
        }

        if (p.type === "api_key" && p.key && !p.keyRef) {
          warnings.push(`${filePath}: Profile "${profileId}" has plaintext key without keyRef`);
        }
      }
    }
  } catch (e) {
    // Ignore JSON parse errors
  }

  return warnings;
}

// ============================================================================
// Main
// ============================================================================

function main() {
  console.log("🔍 Scanning for plaintext secrets...\n");

  let allFindings: Finding[] = [];
  let allWarnings: string[] = [];

  for (const file of CONFIG_FILES) {
    const findings = scanFile(file);
    allFindings = allFindings.concat(findings);

    const warnings = checkRefUsage(file);
    allWarnings = allWarnings.concat(warnings);
  }

  // Report findings
  if (allFindings.length > 0) {
    console.log("❌ PLAINTEXT SECRETS FOUND:\n");

    const critical = allFindings.filter((f) => f.severity === "critical");
    const high = allFindings.filter((f) => f.severity === "high");
    const medium = allFindings.filter((f) => f.severity === "medium");

    if (critical.length > 0) {
      console.log("🔴 CRITICAL:");
      for (const f of critical) {
        console.log(`   ${f.file}:${f.line}`);
        console.log(`      ${f.pattern}: ${f.match}`);
      }
      console.log();
    }

    if (high.length > 0) {
      console.log("🟠 HIGH:");
      for (const f of high) {
        console.log(`   ${f.file}:${f.line}`);
        console.log(`      ${f.pattern}: ${f.match}`);
      }
      console.log();
    }

    if (medium.length > 0) {
      console.log("🟡 MEDIUM:");
      for (const f of medium) {
        console.log(`   ${f.file}:${f.line}`);
        console.log(`      ${f.pattern}: ${f.match}`);
      }
      console.log();
    }
  }

  // Report warnings
  if (allWarnings.length > 0) {
    console.log("⚠️  CONFIGURATION WARNINGS:\n");
    for (const w of allWarnings) {
      console.log(`   ${w}`);
    }
    console.log();
  }

  // Summary
  if (allFindings.length === 0 && allWarnings.length === 0) {
    console.log("✅ No plaintext secrets found!");
    console.log("✅ All credentials are using secret refs.");
    process.exit(0);
  } else {
    const criticalCount = allFindings.filter((f) => f.severity === "critical").length;
    console.log(
      `\n📊 Summary: ${allFindings.length} secret(s) found, ${allWarnings.length} warning(s)`,
    );

    if (criticalCount > 0) {
      console.log("\n⛔ CRITICAL secrets must be moved to the vault before committing!");
      process.exit(1);
    }

    process.exit(allFindings.length > 0 ? 1 : 0);
  }
}

main();
