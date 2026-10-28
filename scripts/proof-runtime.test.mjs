import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertArgv, describeFile, operatorExecutionEnvironment, portableRelativePath, runBounded } from "./lib/proof-runtime.mjs";

test("proof runtime rejects path escape, absolute paths, symlinks, and secret-bearing argv", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-proof-runtime-"));
  fs.writeFileSync(path.join(root, "input.txt"), "safe\n");
  fs.symlinkSync("input.txt", path.join(root, "link.txt"));
  assert.equal(portableRelativePath("a/b.txt"), "a/b.txt");
  assert.throws(() => portableRelativePath("../escape"), /portable relative path/);
  assert.throws(() => portableRelativePath(path.resolve(root, "input.txt")), /portable relative path/);
  assert.throws(() => describeFile(root, "link.txt"), /symbolic link/);
  assert.throws(() => assertArgv(["tool", ["api", "_key=abcdefghijklmnop"].join("")]), /secret material/);
});

test("proof runtime hashes exact bytes and bounds direct execution without a shell", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-proof-runtime-"));
  fs.writeFileSync(path.join(root, "input.txt"), "safe\n");
  const descriptor = describeFile(root, "input.txt");
  assert.equal(descriptor.path, "input.txt");
  assert.match(descriptor.digest, /^sha256:[0-9a-f]{64}$/);
  const result = runBounded(process.execPath, ["-e", "process.stdout.write(JSON.stringify({ok:true}))"], {
    cwd: root,
    input: "",
    environment: {},
    timeoutMs: 2_000,
    maxOutputBytes: 1_024,
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, '{"ok":true}');
  assert.equal(result.timedOut, false);
  assert.throws(() => runBounded(process.execPath, ["-e", "process.stdout.write('x'.repeat(2048))"], {
    cwd: root,
    environment: {},
    timeoutMs: 2_000,
    maxOutputBytes: 128,
  }), /output exceeded/);
  const npm = runBounded(process.platform === "win32" ? "npm.cmd" : "npm", ["--version"], { cwd: root, environment: operatorExecutionEnvironment(), timeoutMs: 5_000, maxOutputBytes: 1024 });
  assert.equal(npm.exitCode, 0);
});
