import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export class MissionLockError extends Error {
  constructor(message) {
    super(message);
    this.name = "MissionLockError";
    this.exitCode = 5;
  }
}

function release(lockPath, fileSystem = fs) {
  fileSystem.rmSync(lockPath, { recursive: true, force: true });
}

function liveOwner(lockPath, fileSystem = fs) {
  try {
    const owner = JSON.parse(fileSystem.readFileSync(path.join(lockPath, "owner.json"), "utf8"));
    if (!Number.isInteger(owner.pid)) return false;
    if (owner.hostname && owner.hostname !== os.hostname()) return true;
    process.kill(owner.pid, 0);
    return true;
  } catch (error) {
    if (error.code === "EPERM") return true;
    return false;
  }
}

function acquire(lockPath, { staleMs, now, fileSystem }) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      fileSystem.mkdirSync(lockPath);
      return;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }

    let age;
    try {
      age = now - fileSystem.statSync(lockPath).mtimeMs;
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }

    if (age <= staleMs || liveOwner(lockPath, fileSystem)) {
      throw new MissionLockError(`Mission is locked by another live process or recent writer: ${lockPath}`);
    }

    release(lockPath, fileSystem);
  }
  throw new MissionLockError(`Mission lock changed repeatedly during acquisition: ${lockPath}`);
}

export function withMissionLock(missionDir, callback, { staleMs = 30 * 60 * 1000, now = Date.now(), fileSystem = fs } = {}) {
  fileSystem.mkdirSync(missionDir, { recursive: true });
  const lockPath = path.join(missionDir, ".tugboat-lock");
  acquire(lockPath, { staleMs, now, fileSystem });
  fileSystem.writeFileSync(path.join(lockPath, "owner.json"), `${JSON.stringify({ pid: process.pid, hostname: os.hostname(), acquiredAt: new Date(now).toISOString() })}\n`);
  try {
    const result = callback();
    if (result && typeof result.then === "function") return result.finally(() => release(lockPath, fileSystem));
    release(lockPath, fileSystem);
    return result;
  } catch (error) {
    release(lockPath, fileSystem);
    throw error;
  }
}
