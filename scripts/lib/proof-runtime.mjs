import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { assertNoSecrets, assertNoSecretsInBuffer } from "./security.mjs";

const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_ARG_BYTES = 16 * 1024;

export function portableRelativePath(value, label = "Path") {
  if (typeof value !== "string" || !value || value.includes("\\") || path.posix.isAbsolute(value) || path.win32.isAbsolute(value)) {
    throw new Error(`${label} must be a portable relative path`);
  }
  const parts = value.split("/");
  if (parts.some((part) => !part || part === "." || part === "..")) throw new Error(`${label} must be a portable relative path`);
  if (Buffer.byteLength(value) > 4096 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error(`${label} is unsafe`);
  return value;
}

export function resolvePortable(rootDir, relative, { mustExist = true, regularFile = false } = {}) {
  const safe = portableRelativePath(relative);
  const root = fs.realpathSync(rootDir);
  const candidate = path.resolve(root, ...safe.split("/"));
  const relation = path.relative(root, candidate);
  if (!relation || relation.startsWith("..") || path.isAbsolute(relation)) throw new Error("Path escapes the declared root");
  if (!mustExist) return candidate;
  const stat = fs.lstatSync(candidate);
  if (stat.isSymbolicLink()) throw new Error(`${relative} is a symbolic link`);
  const real = fs.realpathSync(candidate);
  const realRelation = path.relative(root, real);
  if (realRelation.startsWith("..") || path.isAbsolute(realRelation)) throw new Error(`${relative} escapes through a symbolic link`);
  if (regularFile && !stat.isFile()) throw new Error(`${relative} is not a regular file`);
  return candidate;
}

export function describeFile(rootDir, relative, { maxBytes = MAX_FILE_BYTES } = {}) {
  const file = resolvePortable(rootDir, relative, { regularFile: true });
  const stat = fs.statSync(file);
  if (stat.size > maxBytes) throw new Error(`${relative} exceeds ${maxBytes} bytes`);
  const contents = fs.readFileSync(file);
  assertNoSecretsInBuffer(contents, relative);
  return { path: portableRelativePath(relative), bytes: contents.length, digest: `sha256:${sha256(contents)}` };
}

export function assertArgv(argv) {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > 128) throw new Error("Command argv must contain 1 to 128 items");
  for (const [index, value] of argv.entries()) {
    if (typeof value !== "string" || !value || Buffer.byteLength(value) > MAX_ARG_BYTES || value.includes("\0")) {
      throw new Error(`Command argv[${index}] is invalid`);
    }
  }
  assertNoSecrets(argv, "Command argv");
  return argv;
}

export function operatorExecutionEnvironment() {
  const directories = [path.dirname(process.execPath), ...(process.platform === "win32" ? [] : ["/usr/local/bin", "/usr/bin", "/bin"])];
  return {
    PATH: [...new Set(directories)].join(path.delimiter),
    ...(process.platform === "win32" ? { PATHEXT: ".COM;.EXE;.BAT;.CMD" } : {}),
  };
}

export function runBounded(executable, args = [], {
  cwd,
  input = "",
  environment = {},
  timeoutMs = 30_000,
  maxOutputBytes = 1024 * 1024,
} = {}) {
  assertArgv([executable, ...args]);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) throw new Error("timeoutMs must be an integer from 1 to 300000");
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 64 || maxOutputBytes > 16 * 1024 * 1024) throw new Error("maxOutputBytes is out of range");
  assertNoSecrets(environment, "Execution environment");
  const result = spawnSync(executable, args, {
    cwd,
    input,
    encoding: "utf8",
    env: { ...environment },
    shell: false,
    timeout: timeoutMs,
    maxBuffer: maxOutputBytes + 1,
    windowsHide: true,
  });
  if (result.error?.code === "ENOBUFS" || Buffer.byteLength(result.stdout ?? "") > maxOutputBytes || Buffer.byteLength(result.stderr ?? "") > maxOutputBytes) {
    throw new Error(`Command output exceeded ${maxOutputBytes} bytes`);
  }
  if (result.error && result.error.code !== "ETIMEDOUT") throw result.error;
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  assertNoSecrets(stdout, "Command stdout");
  assertNoSecrets(stderr, "Command stderr");
  return {
    exitCode: Number.isInteger(result.status) ? result.status : null,
    signal: result.signal ?? null,
    timedOut: result.error?.code === "ETIMEDOUT",
    stdout,
    stderr,
    stdoutDigest: `sha256:${sha256(stdout)}`,
    stderrDigest: `sha256:${sha256(stderr)}`,
  };
}

export function canonicalDigest(value) {
  assertNoSecrets(value, "Canonical value");
  return `sha256:${sha256(canonicalJson(value))}`;
}

export function exactObject(value, label, allowed, required = []) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Error(`Unknown ${label} field ${key}`);
  for (const key of required) if (value[key] === undefined || value[key] === null || value[key] === "") throw new Error(`${label} is missing ${key}`);
  assertNoSecrets(value, label);
  return value;
}
