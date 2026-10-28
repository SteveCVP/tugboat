import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

function resolvedFile(file) {
  try {
    return fs.realpathSync(file);
  } catch {
    return path.resolve(file);
  }
}

export function isMainModule(importMetaUrl, argvPath = process.argv[1]) {
  if (!argvPath) return false;
  return resolvedFile(fileURLToPath(importMetaUrl)) === resolvedFile(argvPath);
}
