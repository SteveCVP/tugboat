import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

function git(cwd, args) {
  try {
    return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    return null;
  }
}

export function resolveMissionWorkspace(missionDir, state) {
  const absoluteMissionDir = fs.realpathSync(path.resolve(missionDir));
  const discoveredWorktree = git(absoluteMissionDir, ["rev-parse", "--show-toplevel"]);
  const localWorktree = discoveredWorktree ? fs.realpathSync(discoveredWorktree) : null;
  const relativeMissionDir = localWorktree ? path.relative(localWorktree, absoluteMissionDir) : null;
  const hasBaseline = localWorktree
    ? git(localWorktree, ["rev-parse", "--verify", `${state.metadata.baselineGitSha}^{commit}`])
    : null;
  if (localWorktree && relativeMissionDir !== null && !relativeMissionDir.startsWith("..") && !path.isAbsolute(relativeMissionDir) && hasBaseline) {
    return { repository: localWorktree, worktree: localWorktree, missionDir: absoluteMissionDir };
  }
  return {
    repository: state.metadata.repository,
    worktree: state.metadata.worktree,
    missionDir: absoluteMissionDir,
  };
}
