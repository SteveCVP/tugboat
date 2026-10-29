import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createBoundaryManifest } from "./lib/boundary-manifest.mjs";
import { canonicalJson, sha256 } from "./lib/canonical.mjs";
import { createCertifiedEnvelope } from "./lib/certified-changeset.mjs";
import { explainRollbackHistory } from "./lib/history-debugger.mjs";
import {
  proveRollbackEquivalence,
  verifyRollbackCertificate,
} from "./lib/rollback-equivalence.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function commit(cwd, message) {
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]);
}

function contentAddress(value) {
  const body = structuredClone(value);
  delete body.digest;
  return { ...body, digest: `sha256:${sha256(canonicalJson(body))}` };
}

function boundaryManifest(repository, { id = "manifest:rollback-test", interfaceKind = "source_code", paths = ["app.txt", "schema.sql"] } = {}) {
  const interfacePath = "app.txt";
  const digest = `sha256:${sha256(fs.readFileSync(path.join(repository, interfacePath)))}`;
  return createBoundaryManifest({
    id,
    generatedAt: "2026-10-29T17:00:00.000Z",
    disclosure: "internal",
    sources: [],
    components: [{
      id: "component:rollback",
      owner: "team:platform",
      disclosure: "internal",
      paths,
      requirementIds: ["R7"],
      dependencies: [],
      interfaces: [{ id: "interface:rollback", kind: interfaceKind, path: interfacePath, digest, disclosure: "internal" }],
      invariantIds: ["invariant:rollback"],
      gateIds: ["gate:rollback"],
    }],
    invariants: [{ id: "invariant:rollback", kind: "behavior", description: "Rollback restores the owned change surface.", subjectIds: ["component:rollback"], gateIds: ["gate:rollback"] }],
    gates: [{ id: "gate:rollback", kind: "test", description: "Repository-backed rollback equivalence is mandatory.", subjectIds: ["component:rollback"], mandatory: true }],
  });
}

function fixture() {
  const repository = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-rollback-repository-"));
  git(repository, ["init", "-b", "main"]);
  git(repository, ["config", "user.email", "rollback@example.invalid"]);
  git(repository, ["config", "user.name", "Rollback Test"]);
  fs.writeFileSync(path.join(repository, "app.txt"), "base\n");
  fs.writeFileSync(path.join(repository, "schema.sql"), "CREATE TABLE items (id INTEGER);\n");
  const base = commit(repository, "base");
  fs.writeFileSync(path.join(repository, "app.txt"), "forward\n");
  const forward = commit(repository, "forward change");
  fs.writeFileSync(path.join(repository, "app.txt"), "base\n");
  const declaredRollback = commit(repository, "declared rollback");

  git(repository, ["switch", "-c", "bad-rollback", forward]);
  fs.writeFileSync(path.join(repository, "app.txt"), "wrong\n");
  const badRollback = commit(repository, "bad rollback");
  git(repository, ["switch", "main"]);

  git(repository, ["switch", "--detach", base]);
  const boundary = boundaryManifest(repository);
  git(repository, ["switch", "main"]);
  const policy = contentAddress({ id: "policy:rollback-equivalent", requiredStatus: "equivalent" });
  return { repository, base, forward, declaredRollback, badRollback, boundary, policy };
}

function options(context, overrides = {}) {
  return {
    repository: context.repository,
    baseRef: context.base,
    forwardCommits: [context.forward],
    rollback: { mode: "exact_inverse", commits: [] },
    boundary: context.boundary,
    policy: context.policy,
    runtimeEffects: [],
    producer: { name: "Operator", kind: "human", runtime: "test" },
    generatedAt: "2026-10-29T18:00:00.000Z",
    ...overrides,
  };
}

function snapshot(context) {
  return {
    head: git(context.repository, ["rev-parse", "HEAD"]),
    branch: git(context.repository, ["branch", "--show-current"]),
    status: git(context.repository, ["status", "--porcelain=v1", "--untracked-files=all"]),
    app: fs.readFileSync(path.join(context.repository, "app.txt"), "utf8"),
    worktrees: git(context.repository, ["worktree", "list", "--porcelain"]),
  };
}

test("exact inverse proves boundary-observable equivalence without changing target bytes", () => {
  const context = fixture();
  const before = snapshot(context);
  const result = proveRollbackEquivalence(options(context));
  assert.equal(result.status, "equivalent");
  assert.equal(result.certificate.payload.verdict, "ready");
  assert.equal(result.certificate.payload.body.observations.base.digest, result.certificate.payload.body.observations.rolledBack.digest);
  assert.deepEqual(result.certificate.payload.body.mismatches, []);
  assert.equal(result.certificate.payload.body.execution.disposableWorktree, true);
  assert.equal(result.certificate.payload.body.execution.forwardApplied, true);
  assert.equal(result.certificate.payload.body.execution.rollbackApplied, true);
  assert.equal(verifyRollbackCertificate(result.certificate, { repository: context.repository }).status, "equivalent");
  assert.deepEqual(snapshot(context), before);
});

test("a declared rollback can prove equivalence and is bound to its exact operation", () => {
  const context = fixture();
  const result = proveRollbackEquivalence(options(context, {
    rollback: { mode: "declared", commits: [context.declaredRollback] },
  }));
  assert.equal(result.status, "equivalent");
  assert.deepEqual(result.certificate.payload.body.rollback, { mode: "declared", commits: [context.declaredRollback] });
  assert.equal(result.certificate.payload.body.effectAssessments[0].status, "equivalent");
});

test("exact inverse and repository verification agree on no-op commits in the forward range", () => {
  const context = fixture();
  git(context.repository, ["switch", "-c", "empty-forward", context.forward]);
  git(context.repository, ["commit", "--allow-empty", "-m", "forward no-op"]);
  const emptyForward = git(context.repository, ["rev-parse", "HEAD"]);
  git(context.repository, ["switch", "main"]);
  const result = proveRollbackEquivalence(options(context, { forwardCommits: [context.forward, emptyForward] }));
  assert.equal(result.status, "equivalent");
  assert.deepEqual(result.certificate.payload.body.forwardCommits, [context.forward, emptyForward]);
  assert.equal(verifyRollbackCertificate(result.certificate, { repository: context.repository }).status, "equivalent");
});

test("transient semantic changes remain in the effect footprint even when the final tree removes them", () => {
  const context = fixture();
  git(context.repository, ["switch", "-c", "transient-migration", context.base]);
  fs.mkdirSync(path.join(context.repository, "migrations"));
  fs.writeFileSync(path.join(context.repository, "migrations", "001.sql"), "ALTER TABLE items ADD COLUMN name TEXT;\n");
  const addMigration = commit(context.repository, "add transient migration");
  fs.rmSync(path.join(context.repository, "migrations", "001.sql"));
  const removeMigration = commit(context.repository, "remove transient migration");
  git(context.repository, ["switch", "main"]);
  const boundary = createBoundaryManifest({
    id: "manifest:transient-migration",
    generatedAt: "2026-10-29T17:15:00.000Z",
    disclosure: "internal",
    sources: [],
    components: [{ id: "component:migrations", owner: "team:platform", disclosure: "internal", paths: ["migrations/**"], requirementIds: ["R7"], dependencies: [], interfaces: [], invariantIds: ["invariant:rollback"], gateIds: ["gate:rollback"] }],
    invariants: [{ id: "invariant:rollback", kind: "behavior", description: "Transient migrations remain visible to rollback assessment.", subjectIds: ["component:migrations"], gateIds: ["gate:rollback"] }],
    gates: [{ id: "gate:rollback", kind: "test", description: "Rollback assessment includes every commit transition.", subjectIds: ["component:migrations"], mandatory: true }],
  });
  const result = proveRollbackEquivalence(options(context, { forwardCommits: [addMigration, removeMigration], boundary }));
  assert.equal(result.status, "insufficient_evidence");
  assert.ok(result.certificate.payload.body.effectAssessments.some((item) => item.kind === "schema" && item.subject === "path:migrations/001.sql"));
  assert.ok(result.certificate.payload.body.effectAssessments.some((item) => item.kind === "data" && item.subject === "path:migrations/001.sql"));
  assert.equal(verifyRollbackCertificate(result.certificate, { repository: context.repository }).status, "insufficient_evidence");
});

test("file mismatch returns not_equivalent with the shortest exact counterexample", () => {
  const context = fixture();
  git(context.repository, ["switch", "-c", "multi-mismatch-rollback", context.forward]);
  fs.writeFileSync(path.join(context.repository, "app.txt"), "wrong\n");
  fs.writeFileSync(path.join(context.repository, "schema.sql"), "DROP TABLE items;\n");
  const multiMismatchRollback = commit(context.repository, "multi-mismatch rollback");
  git(context.repository, ["switch", "main"]);
  const before = snapshot(context);
  const result = proveRollbackEquivalence(options(context, { rollback: { mode: "declared", commits: [multiMismatchRollback] } }));
  assert.equal(result.status, "not_equivalent");
  assert.equal(result.certificate.payload.verdict, "blocked");
  assert.deepEqual(result.certificate.payload.body.mismatches.map((item) => item.path), ["app.txt", "schema.sql"]);
  assert.equal(result.certificate.payload.counterexamples[0].code, "rollback_state_mismatch");
  assert.equal(result.certificate.payload.counterexamples[0].actual, "app.txt");
  assert.deepEqual(result.certificate.payload.counterexamples[0].subjectIds, ["path:app.txt"]);
  assert.deepEqual(snapshot(context), before);
});

test("irreversible schema and data effects block even when repository bytes are restored", () => {
  for (const kind of ["schema", "data"]) {
    const context = fixture();
    const boundary = boundaryManifest(context.repository, { id: `manifest:${kind}-rollback`, interfaceKind: "sql" });
    const result = proveRollbackEquivalence(options(context, { boundary, runtimeEffects: [{ kind, subject: "interface:rollback", reversibility: "irreversible" }] }));
    assert.equal(result.status, "not_equivalent");
    assert.ok(result.certificate.payload.body.effectAssessments.some((item) => item.kind === kind && item.status === "not_equivalent"));
    assert.ok(result.certificate.payload.counterexamples.some((item) => item.code === "irreversible_effect"));
  }
});

test("unknown infrastructure or external recovery returns insufficient evidence", () => {
  for (const kind of ["infrastructure", "external"]) {
    const context = fixture();
    const boundary = boundaryManifest(context.repository, { id: `manifest:${kind}-rollback`, interfaceKind: kind === "infrastructure" ? "terraform" : "github_actions" });
    const result = proveRollbackEquivalence(options(context, { boundary }));
    assert.equal(result.status, "insufficient_evidence");
    assert.equal(result.certificate.payload.verdict, "insufficient_evidence");
    assert.equal(result.certificate.payload.counterexamples[0].code, "rollback_effect_unknown");
  }
});

test("runtime recovery cannot be relabeled exact or omitted from derived interface obligations", () => {
  for (const kind of ["schema", "data", "infrastructure", "external"]) {
    const context = fixture();
    const interfaceKind = ["schema", "data"].includes(kind) ? "sql" : kind === "infrastructure" ? "terraform" : "github_actions";
    const boundary = boundaryManifest(context.repository, { id: `manifest:${kind}-source-only`, interfaceKind });
    const result = proveRollbackEquivalence(options(context, { boundary, runtimeEffects: [] }));
    assert.equal(result.status, "insufficient_evidence");
    assert.ok(result.certificate.payload.body.effectAssessments.some((item) => item.kind === kind && /cannot prove runtime reversal/i.test(item.reason)));
    assert.throws(() => proveRollbackEquivalence(options(context, { boundary, runtimeEffects: [{ kind, subject: "interface:rollback", reversibility: "exact" }] })), /irreversible or unknown/i);
  }
});

test("exact forward-range coverage rejects changed files outside verified boundary ownership", () => {
  const context = fixture();
  const boundary = createBoundaryManifest({
    id: "manifest:incomplete-ownership",
    generatedAt: "2026-10-29T17:30:00.000Z",
    disclosure: "internal",
    sources: [],
    components: [{ id: "component:schema", owner: "team:platform", disclosure: "internal", paths: ["schema.sql"], requirementIds: ["R7"], dependencies: [], interfaces: [], invariantIds: ["invariant:rollback"], gateIds: ["gate:rollback"] }],
    invariants: [{ id: "invariant:rollback", kind: "behavior", description: "Owned schema bytes are reversible.", subjectIds: ["component:schema"], gateIds: ["gate:rollback"] }],
    gates: [{ id: "gate:rollback", kind: "test", description: "Rollback coverage is mandatory.", subjectIds: ["component:schema"], mandatory: true }],
  });
  assert.throws(() => proveRollbackEquivalence(options(context, { boundary })), /not owned.*app\.txt/i);
});

test("missing declared rollback returns insufficient evidence without target mutation", () => {
  const context = fixture();
  const before = snapshot(context);
  const result = proveRollbackEquivalence(options(context, { rollback: { mode: "declared", commits: [] } }));
  assert.equal(result.status, "insufficient_evidence");
  assert.equal(result.certificate.payload.body.execution.rollbackApplied, false);
  assert.ok(result.certificate.payload.counterexamples.some((item) => item.code === "rollback_operation_missing"));
  assert.deepEqual(snapshot(context), before);
});

test("target drift rejects proof and still removes the disposable worktree", { timeout: 30_000 }, () => {
  const context = fixture();
  const knownRoots = new Set(fs.readdirSync(os.tmpdir()).filter((name) => name.startsWith("tugboat-rollback-")));
  const watcher = spawn(process.execPath, ["-e", `
    const fs = require('node:fs');
    const os = require('node:os');
    const cp = require('node:child_process');
    const known = new Set(${JSON.stringify([...knownRoots])});
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      const found = fs.readdirSync(os.tmpdir()).find(name => name.startsWith('tugboat-rollback-') && !known.has(name));
      if (found) {
        cp.execFileSync('git', ['commit', '--allow-empty', '-m', 'concurrent target drift'], { cwd: ${JSON.stringify(context.repository)}, stdio: 'ignore' });
        process.exit(0);
      }
    }
    process.exit(2);
  `], { stdio: "ignore" });
  let failure;
  try { proveRollbackEquivalence(options(context)); } catch (error) { failure = error; } finally { watcher.kill(); }
  assert.match(failure?.message ?? "", /target.*drift|changed during rollback proof/i);
  assert.equal(failure?.details?.counterexample?.code, "target_drift");
  assert.equal(git(context.repository, ["worktree", "list", "--porcelain"]).split("\nworktree ").length, 1);
});

test("ambient replace refs and grafts cannot redefine certified commit semantics", () => {
  const context = fixture();
  git(context.repository, ["replace", context.forward, context.badRollback]);
  assert.throws(() => proveRollbackEquivalence(options(context)), /replace refs/i);
  git(context.repository, ["replace", "-d", context.forward]);
  const grafts = path.join(path.resolve(context.repository, git(context.repository, ["rev-parse", "--git-dir"])), "info", "grafts");
  fs.mkdirSync(path.dirname(grafts), { recursive: true });
  fs.writeFileSync(grafts, `${context.forward} ${context.base}\n`);
  assert.throws(() => proveRollbackEquivalence(options(context)), /info\/grafts|native commit ancestry/i);
});

test("repository-backed verification rejects ordinary, rehashed, and coherent semantic forgery", () => {
  const context = fixture();
  const result = proveRollbackEquivalence(options(context));
  const ordinary = structuredClone(result.certificate);
  ordinary.payload.body.equivalence = "not_equivalent";
  assert.throws(() => verifyRollbackCertificate(ordinary, { repository: context.repository }), /digest mismatch|tamper/i);

  const rehashedPayload = structuredClone(result.certificate.payload);
  rehashedPayload.body.equivalence = "not_equivalent";
  rehashedPayload.claims[0].status = "failed";
  const rehashed = createCertifiedEnvelope({ format: "tugboat.rollback-equivalence.v1", payload: rehashedPayload });
  assert.throws(() => verifyRollbackCertificate(rehashed, { repository: context.repository }), /equivalence|mismatch|effect assessment|execution/i);

  const relabeledPayload = structuredClone(result.certificate.payload);
  relabeledPayload.claims[0].summary = "Trust me; rollback passed.";
  const relabeled = createCertifiedEnvelope({ format: "tugboat.rollback-equivalence.v1", payload: relabeledPayload });
  assert.throws(() => verifyRollbackCertificate(relabeled, { repository: context.repository }), /claim is inconsistent/i);

  const retypedPayload = structuredClone(result.certificate.payload);
  retypedPayload.inputs[0].kind = "untrusted_boundary";
  const retyped = createCertifiedEnvelope({ format: "tugboat.rollback-equivalence.v1", payload: retypedPayload });
  assert.throws(() => verifyRollbackCertificate(retyped, { repository: context.repository }), /inputs do not bind/i);

  assert.throws(() => verifyRollbackCertificate(result.certificate), /requires the exact local repository/i);

  const fabricatedPayload = structuredClone(result.certificate.payload);
  fabricatedPayload.body.baseHead = "0".repeat(40);
  fabricatedPayload.body.forwardCommits = ["1".repeat(40)];
  const rollback = fabricatedPayload.body.rollback;
  const boundaryDigest = fabricatedPayload.body.boundary.digest;
  const policyDigest = fabricatedPayload.body.policy.digest;
  const runtimeEffects = fabricatedPayload.body.runtimeEffects;
  fabricatedPayload.body.changeDigest = `sha256:${sha256(canonicalJson({ baseHead: fabricatedPayload.body.baseHead, forwardCommits: fabricatedPayload.body.forwardCommits, rollback, boundaryDigest, policyDigest, runtimeEffects }))}`;
  const short = sha256(fabricatedPayload.body.changeDigest).slice(0, 32);
  fabricatedPayload.id = `certificate:rollback-${short}`;
  fabricatedPayload.subjects = [{ kind: "git_range", id: `git_range:rollback-${short}`, digest: fabricatedPayload.body.changeDigest }];
  fabricatedPayload.claims[0].id = `claim:rollback-${short}`;
  fabricatedPayload.claims[0].subjectIds = [`git_range:rollback-${short}`];
  const fabricated = createCertifiedEnvelope({ format: "tugboat.rollback-equivalence.v1", payload: fabricatedPayload });
  assert.throws(() => verifyRollbackCertificate(fabricated, { repository: context.repository }), /Git command failed|commit|object/i);
});

test("policy and rollback certificate are included in a concise history explanation", () => {
  const context = fixture();
  const result = proveRollbackEquivalence(options(context));
  const explanation = explainRollbackHistory(result.certificate, { repository: context.repository });
  assert.equal(explanation.status, "equivalent");
  assert.equal(explanation.certificateDigest, result.certificate.digest);
  assert.equal(explanation.policy.id, context.policy.id);
  assert.deepEqual(explanation.mismatches, []);
  assert.match(explanation.summary, /equivalent/i);
});

test("portable CLI proves and repository-verifies rollback while execution remains explicit", () => {
  const context = fixture();
  const before = snapshot(context);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-rollback-cli-"));
  const manifest = path.join(root, "rollback.json");
  const output = path.join(root, "rollback-certificate.json");
  fs.writeFileSync(manifest, JSON.stringify({
    repository: context.repository,
    baseRef: context.base,
    forwardCommits: [context.forward],
    rollback: { mode: "exact_inverse", commits: [] },
    boundary: context.boundary,
    policy: context.policy,
    generatedAt: "2026-10-29T18:01:00.000Z",
  }));
  const cli = path.resolve("scripts/tugboat.mjs");
  const proved = JSON.parse(execFileSync(process.execPath, [cli, "rollback", "prove", "--manifest", manifest, "--output", output, "--json"], { encoding: "utf8" }));
  assert.equal(proved.status, "equivalent");
  assert.equal(fs.existsSync(output), true);
  const verified = JSON.parse(execFileSync(process.execPath, [cli, "certificate", "verify-rollback", "--file", output, "--repository", context.repository, "--json"], { encoding: "utf8" }));
  assert.equal(verified.status, "equivalent");
  const history = JSON.parse(execFileSync(process.execPath, [cli, "history", "explain", "--rollback-certificate", output, "--repository", context.repository, "--json"], { encoding: "utf8" }));
  assert.equal(history.status, "equivalent");
  assert.equal(history.certificateDigest, proved.certificate.digest);
  assert.deepEqual(snapshot(context), before);
});

test("certificate output cannot create an untracked mutation inside the target", () => {
  const context = fixture();
  const before = snapshot(context);
  const outputPath = path.join(context.repository, "rollback-certificate.json");
  assert.throws(() => proveRollbackEquivalence(options(context, { outputPath })), /output must be outside the target repository/i);
  assert.equal(fs.existsSync(outputPath), false);
  assert.deepEqual(snapshot(context), before);
});

test("certificate publication never overwrites an existing evidence artifact", () => {
  const context = fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-rollback-evidence-"));
  const outputPath = path.join(root, "rollback-certificate.json");
  fs.writeFileSync(outputPath, "existing evidence\n");
  const before = snapshot(context);
  assert.throws(() => proveRollbackEquivalence(options(context, { outputPath })), /already exists.*overwrite evidence/i);
  assert.equal(fs.readFileSync(outputPath, "utf8"), "existing evidence\n");
  assert.deepEqual(snapshot(context), before);
});
