import os from "node:os";

const PATTERNS = [
  { kind: "private-key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, replacement: "[REDACTED PRIVATE KEY]" },
  { kind: "aws-access-key", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replacement: "[REDACTED AWS ACCESS KEY]" },
  { kind: "github-token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b/g, replacement: "[REDACTED GITHUB TOKEN]" },
  { kind: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, replacement: "[REDACTED JWT]" },
  { kind: "bearer-token", regex: /\bBearer\s+[A-Za-z0-9._~+\/-]{24,}/gi, replacement: "Bearer [REDACTED]" },
  { kind: "secret-value", regex: /\b(?:api[_-]?key|client[_-]?secret|password|webhook[_-]?secret|access[_-]?token)\s*[:=]\s*["']?[A-Za-z0-9._~+\/-]{12,}["']?/gi, replacement: "[REDACTED SECRET VALUE]" },
];

export function scanSecrets(value) {
  const text = String(value ?? "");
  const findings = [];
  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    for (const match of text.matchAll(pattern.regex)) {
      findings.push({ kind: pattern.kind, index: match.index, length: match[0].length });
    }
  }
  return findings.sort((left, right) => left.index - right.index);
}

export function redactSecrets(value) {
  let text = String(value ?? "");
  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    text = text.replace(pattern.regex, pattern.replacement);
  }
  return text;
}

export function assertNoSecrets(value, label = "value") {
  const findings = scanSecrets(typeof value === "string" ? value : JSON.stringify(value));
  const seen = new Set();
  function visit(item) {
    if (typeof item === "string") {
      findings.push(...scanSecrets(item));
      return;
    }
    if (Buffer.isBuffer(item)) {
      if (isTextBuffer(item)) findings.push(...scanSecrets(item.toString("utf8")));
      return;
    }
    if (!item || typeof item !== "object" || seen.has(item)) return;
    seen.add(item);
    if (Array.isArray(item)) item.forEach(visit);
    else for (const [key, child] of Object.entries(item)) {
      findings.push(...scanSecrets(key));
      visit(child);
    }
  }
  if (typeof value !== "string") visit(value);
  if (findings.length) {
    const kinds = [...new Set(findings.map((finding) => finding.kind))].join(", ");
    throw new Error(`${label} contains secret material (${kinds}); store a redacted reference instead`);
  }
}

export function isTextBuffer(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value ?? "");
  if (buffer.includes(0)) return false;
  const text = buffer.toString("utf8");
  return Buffer.from(text, "utf8").equals(buffer);
}

export function assertNoSecretsInBuffer(value, label = "value") {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value ?? "");
  if (isTextBuffer(buffer)) assertNoSecrets(buffer.toString("utf8"), label);
}

export function resolveActor({ explicit, env = process.env, gitName = "", userName = os.userInfo().username } = {}) {
  if (explicit) return { name: explicit, kind: "human", runtime: env.TUGBOAT_RUNTIME || "explicit" };
  if (env.TUGBOAT_ACTOR) return { name: env.TUGBOAT_ACTOR, kind: "agent", runtime: env.TUGBOAT_RUNTIME || "agent" };
  if (env.GITHUB_ACTIONS === "true" && env.GITHUB_ACTOR) return { name: env.GITHUB_ACTOR, kind: "ci", runtime: "github-actions" };
  if (env.CI === "true" || env.CI === "1") return { name: env.CI_ACTOR || "ci", kind: "ci", runtime: env.CI_PROVIDER || "ci" };
  if (gitName) return { name: gitName, kind: "git", runtime: "shell" };
  return { name: userName || "unknown", kind: "os", runtime: "shell" };
}
