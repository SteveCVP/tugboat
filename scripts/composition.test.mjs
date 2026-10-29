import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createBundle, readBundle } from "./lib/bundle.mjs";
import { analyzeCertifiedChange } from "./lib/analyzer-protocol.mjs";
import { createBoundaryManifest, writeBoundaryManifest } from "./lib/boundary-manifest.mjs";
import {
  composeBundles,
  planComposition,
  verifyCompositionCertificate,
  verifyMergeCertificate,
} from "./lib/composition.mjs";
import { canonicalJson, sha256 } from "./lib/canonical.mjs";
import { createCertifiedEnvelope } from "./lib/certified-changeset.mjs";
import { explainMissionHistory } from "./lib/history-debugger.mjs";
import { certifyBundleNonInterference, verifyBundleNonInterference, writeNonInterferenceWitness } from "./lib/non-interference.mjs";
import { createMission, missionReducer } from "./lib/reducer.mjs";
import { renderMission } from "./lib/render.mjs";
import { appendEvent, readState, replayEvents } from "./lib/store.mjs";

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function commit(cwd, message) {
  git(cwd, ["add", "-A"]);
  git(cwd, ["commit", "-m", message]);
  return git(cwd, ["rev-parse", "HEAD"]);
}

function initRepo(prefix) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.email", "composition@example.invalid"]);
  git(repo, ["config", "user.name", "Composition Test"]);
  return repo;
}

function createTestMission(repo, dirName, id, requirements, baseline) {
  const missionDir = path.join(repo, dirName);
  createMission({
    dir: missionDir,
    actor: { name: "Test", kind: "human", runtime: "test" },
    metadata: {
      id, title: id, owner: "Test", target: "local", repository: repo, worktree: repo, branch: "main", baselineGitSha: baseline,
      source: { path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(repo, "spec.md")))}` },
      criticalPath: requirements.map((item) => item.id), deployPath: "not requested",
    },
    requirements,
    preservations: [],
    slices: [{ id: "S1", name: "Composition", requirementIds: requirements.map((item) => item.id), dependencies: [], status: "ACTIVE", operatorJourney: "Compose candidates" }],
  });
  commit(repo, `initialize ${id}`);
  return missionDir;
}

function witness(bundle, effects) {
  const body = {
    bundleId: bundle.payload.id,
    bundleDigest: bundle.digest,
    boundaryManifestDigest: `sha256:${"b".repeat(64)}`,
    effects,
    uncertainty: [],
    provenUnaffectedComponentIds: [],
  };
  const envelope = createCertifiedEnvelope({ format: "tugboat.non-interference-witness.v1", payload: {
    id: `certificate:non-interference-${bundle.payload.id}`,
    generatedAt: "2026-10-29T11:59:00.000Z",
    verdict: "ready",
    subjects: [{ kind: "bundle", id: `bundle:${bundle.payload.id}`, digest: bundle.digest }],
    inputs: [{ kind: "boundary_manifest", id: "manifest:test", digest: body.boundaryManifestDigest }],
    producer: { name: "Fixture", kind: "test", runtime: "node" },
    claims: [{ id: `claim:non-interference-${bundle.payload.id}`, type: "non_interference", status: "passed", subjectIds: [`bundle:${bundle.payload.id}`], summary: "Fixture effects are bound to the exact bundle." }],
    counterexamples: [],
    body,
  } });
  return {
    semanticProof: true,
    verdict: "ready",
    digest: envelope.digest,
    payload: envelope.payload,
  };
}

function effect(id, subject) {
  return { id, domain: "path", subject, access: "write", operation: "create", sourceDigest: `sha256:${sha256(id)}` };
}

function proofGraph(bundle, verifiedWitness, extraGates = []) {
  const effectIds = verifiedWitness.payload.body.effects.map((item) => item.id);
  return {
    schemaVersion: "tugboat.proof-invalidation-graph.v1",
    bundleDigest: bundle.digest,
    boundaryManifestDigest: verifiedWitness.payload.body.boundaryManifestDigest,
    nodes: [
      ...effectIds.map((id) => ({ id, kind: "effect", mandatory: false })),
      { id: "gate:selected", kind: "gate", mandatory: false },
      { id: "gate:mandatory", kind: "gate", mandatory: true },
      ...extraGates.map((gate) => ({ id: gate.id, kind: "gate", mandatory: gate.mandatory })),
    ],
    edges: effectIds.map((id) => ({ from: id, to: "gate:selected", kind: "invalidates" })),
  };
}

function fixture({ divergent = false, orderDivergent = false, dependent = false, withCli = false, semanticSql = false, renameSql = false, multiRequirementClaude = false, subjectOnlyGate = false, candidateCount = 2 } = {}) {
  if (!Number.isInteger(candidateCount) || candidateCount < 2 || candidateCount > 5) throw new Error("candidateCount must be from 2 to 5");
  const additionalCandidateIds = Array.from({ length: candidateCount - 2 }, (_, index) => index + 1);
  const requirements = [
    { id: "SRC-CLAUDE", requirement: "Claude candidate", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    { id: "SRC-CODEX", requirement: "Codex candidate", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    ...(multiRequirementClaude ? [{ id: "SRC-EXTRA", requirement: "Additional Claude scope", source: "spec", material: true, acceptance: "works", proofTarget: "local" }] : []),
    ...additionalCandidateIds.map((index) => ({ id: `SRC-AGENT-${index}`, requirement: `Agent ${index} candidate`, source: "spec", material: true, acceptance: "works", proofTarget: "local" })),
  ];
  const source = initRepo("tugboat-composition-source-");
  fs.writeFileSync(path.join(source, "spec.md"), "# Composition source\n");
  fs.writeFileSync(path.join(source, "stable.txt"), divergent || orderDivergent ? "base\n" : "stable\n");
  if (renameSql) {
    fs.mkdirSync(path.join(source, "candidate"), { recursive: true });
    fs.writeFileSync(path.join(source, "candidate", "claude-old.sql"), "CREATE TABLE companies (id INTEGER);\n");
  }
  if (orderDivergent) fs.writeFileSync(path.join(source, ".gitattributes"), "stable.txt merge=union\n");
  const sourceBaseline = commit(source, "source baseline");
  const sourceMission = createTestMission(source, "source-mission", "composition-source", requirements, sourceBaseline);
  const artifactRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-source-artifacts-"));

  const claudeTargetPath = semanticSql || renameSql ? "candidate/claude.sql" : "candidate/claude.txt";
  if (divergent || orderDivergent) fs.writeFileSync(path.join(source, "stable.txt"), "claude\n");
  else if (renameSql) {
    fs.renameSync(path.join(source, "candidate", "claude-old.sql"), path.join(source, ...claudeTargetPath.split("/")));
    fs.writeFileSync(path.join(source, ...claudeTargetPath.split("/")), "CREATE TABLE companies (id INTEGER, name TEXT);\n");
  }
  else {
    fs.mkdirSync(path.join(source, "candidate"), { recursive: true });
    fs.writeFileSync(path.join(source, ...claudeTargetPath.split("/")), semanticSql ? "CREATE TABLE companies (id INTEGER, name TEXT);\n" : "claude result\n");
  }
  const claudeCommit = commit(source, "Claude candidate");
  const claudePath = path.join(artifactRoot, "claude.tugboat.json");
  createBundle({
    missionDir: sourceMission, id: "B-CLAUDE", outputPath: claudePath, requirementIds: ["SRC-CLAUDE", ...(multiRequirementClaude ? ["SRC-EXTRA"] : [])], commitShas: [claudeCommit],
    actor: { name: "Claude", kind: "agent", runtime: "claude" }, createdAt: "2026-10-29T12:00:00.000Z",
  });

  const additionalBundles = [];
  for (const index of additionalCandidateIds) {
    const candidatePath = `candidate/agent-${index}.txt`;
    fs.writeFileSync(path.join(source, ...candidatePath.split("/")), `agent ${index} result\n`);
    const candidateCommit = commit(source, `Agent ${index} candidate`);
    const bundlePath = path.join(artifactRoot, `agent-${index}.tugboat.json`);
    createBundle({
      missionDir: sourceMission,
      id: `B-AGENT-${index}`,
      outputPath: bundlePath,
      requirementIds: [`SRC-AGENT-${index}`],
      commitShas: [candidateCommit],
      actor: { name: `Agent ${index}`, kind: "agent", runtime: "test" },
      createdAt: `2026-10-29T12:0${index + 1}:00.000Z`,
    });
    additionalBundles.push({ index, candidatePath, candidateCommit, bundlePath });
  }

  if (divergent || orderDivergent) {
    git(source, ["checkout", `${claudeCommit}^`, "--", "stable.txt"]);
    commit(source, "restore source baseline");
    fs.writeFileSync(path.join(source, "stable.txt"), "codex\n");
  } else fs.writeFileSync(path.join(source, "candidate", "codex.txt"), "codex result\n");
  const codexCommit = commit(source, "Codex candidate");
  const codexPath = path.join(artifactRoot, "codex.tugboat.json");
  createBundle({
    missionDir: sourceMission, id: "B-CODEX", outputPath: codexPath, requirementIds: ["SRC-CODEX"], commitShas: [codexCommit],
    dependsOn: dependent ? ["B-CLAUDE"] : [],
    actor: { name: "Codex", kind: "agent", runtime: "codex" }, createdAt: "2026-10-29T12:01:00.000Z",
  });

  const target = initRepo("tugboat-composition-target-");
  fs.writeFileSync(path.join(target, "spec.md"), "# Composition target\n");
  fs.writeFileSync(path.join(target, "stable.txt"), divergent || orderDivergent ? "base\n" : "stable\n");
  if (renameSql) {
    fs.mkdirSync(path.join(target, "candidate"), { recursive: true });
    fs.writeFileSync(path.join(target, "candidate", "claude-old.sql"), "CREATE TABLE companies (id INTEGER);\n");
  }
  if (orderDivergent) fs.writeFileSync(path.join(target, ".gitattributes"), "stable.txt merge=union\n");
  const targetBaseline = commit(target, "target baseline");
  const targetRequirements = [
    { id: "R-CLAUDE", requirement: "Claude result", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    { id: "R-CODEX", requirement: "Codex result", source: "spec", material: true, acceptance: "works", proofTarget: "local" },
    ...(multiRequirementClaude ? [{ id: "R-EXTRA", requirement: "Additional Claude result", source: "spec", material: true, acceptance: "works", proofTarget: "local" }] : []),
    ...additionalCandidateIds.map((index) => ({ id: `R-AGENT-${index}`, requirement: `Agent ${index} result`, source: "spec", material: true, acceptance: "works", proofTarget: "local" })),
  ];
  const targetMission = createTestMission(target, "target-mission", "composition-target", targetRequirements, targetBaseline);
  const claude = readBundle(claudePath);
  const codex = readBundle(codexPath);
  const declaredClaudePath = divergent || orderDivergent ? "declared/claude" : claudeTargetPath;
  const declaredCodexPath = divergent || orderDivergent ? "declared/codex" : "candidate/codex.txt";
  const claudeWitness = witness(claude, renameSql ? [{
    id: "effect:claude",
    level: "file",
    operation: "rename",
    path: declaredClaudePath,
    previousPath: "candidate/claude-old.sql",
    bundleId: "B-CLAUDE",
    sourceKind: "patch",
    sourceId: claudeCommit,
    sourceDigest: `sha256:${sha256("effect:claude")}`,
    requirementIds: ["SRC-CLAUDE"],
  }] : [effect("effect:claude", declaredClaudePath)]);
  const codexWitness = witness(codex, [effect("effect:codex", declaredCodexPath)]);
  const candidates = [
    {
      bundlePath: claudePath,
      requirementIds: ["SRC-CLAUDE"],
      mappings: { "SRC-CLAUDE": "R-CLAUDE" },
      witness: claudeWitness,
      proofGraph: proofGraph(claude, claudeWitness),
      policyGates: [{ id: "gate:mandatory", kind: "test", mandatory: true }, { id: "gate:selected", kind: "test", mandatory: false }],
      policyRequiredInvalidatedGateIds: ["gate:mandatory", "gate:selected"],
      analyzerObligations: [],
    },
    {
      bundlePath: codexPath,
      requirementIds: ["SRC-CODEX"],
      mappings: { "SRC-CODEX": "R-CODEX" },
      witness: codexWitness,
      proofGraph: proofGraph(codex, codexWitness),
      policyGates: [{ id: "gate:mandatory", kind: "test", mandatory: true }, { id: "gate:selected", kind: "test", mandatory: false }],
      policyRequiredInvalidatedGateIds: ["gate:mandatory", "gate:selected"],
      analyzerObligations: [],
    },
    ...additionalBundles.map(({ index, candidatePath, candidateCommit, bundlePath }) => {
      const bundle = readBundle(bundlePath);
      const candidateWitness = witness(bundle, [effect(`effect:agent-${index}`, candidatePath)]);
      return {
        bundlePath,
        requirementIds: [`SRC-AGENT-${index}`],
        mappings: { [`SRC-AGENT-${index}`]: `R-AGENT-${index}` },
        witness: candidateWitness,
        proofGraph: proofGraph(bundle, candidateWitness),
        policyGates: [{ id: "gate:mandatory", kind: "test", mandatory: true }, { id: "gate:selected", kind: "test", mandatory: false }],
        policyRequiredInvalidatedGateIds: ["gate:mandatory", "gate:selected"],
        analyzerObligations: [],
      };
    }),
  ];
  if (semanticSql || renameSql) {
    candidates[0].analyzerReports = [analyzeCertifiedChange({
      analyzerId: "sql",
      before: { path: renameSql ? "candidate/claude-old.sql" : claudeTargetPath, source: renameSql ? "CREATE TABLE companies (id INTEGER);\n" : "" },
      after: { path: claudeTargetPath, source: "CREATE TABLE companies (id INTEGER, name TEXT);\n" },
    })];
  }
  let cliCandidates = [];
  if (withCli) {
    const boundary = createBoundaryManifest({
      id: "manifest:composition-fixture",
      generatedAt: "2026-10-29T12:02:00.000Z",
      disclosure: "internal",
      sources: [{ id: "source:spec", path: "spec.md", digest: `sha256:${sha256(fs.readFileSync(path.join(source, "spec.md")))}`, disclosure: "internal" }],
      components: [{ id: "component:text", owner: "team:test", disclosure: "internal", paths: ["candidate/**"], requirementIds: ["SRC-CLAUDE", "SRC-CODEX"], dependencies: [], interfaces: [], invariantIds: ["invariant:text"], gateIds: ["gate:mandatory", "gate:selected"] }],
      invariants: [{ id: "invariant:text", kind: "behavior", description: "Text candidate behavior is preserved.", subjectIds: ["component:text"], gateIds: ["gate:mandatory", "gate:selected"] }],
      gates: [
        { id: "gate:mandatory", kind: "test", description: "Validate mandatory composition behavior.", subjectIds: ["component:text"], mandatory: true },
        { id: "gate:selected", kind: "test", description: "Validate invalidated composition behavior.", subjectIds: ["component:text"], mandatory: false },
        ...(subjectOnlyGate ? [{ id: "gate:subject-only", kind: "test", description: "Validate a subject-linked policy obligation.", subjectIds: ["component:text"], mandatory: false }] : []),
      ],
    });
    const boundaryPath = path.join(artifactRoot, "composition.boundaries.json");
    writeBoundaryManifest(boundaryPath, boundary);
    const claudeWitnessEnvelope = certifyBundleNonInterference({ bundle: claude, boundary, rootDir: source, producer: { name: "Fixture", kind: "test", runtime: "node" }, generatedAt: "2026-10-29T12:03:00.000Z" });
    const codexWitnessEnvelope = certifyBundleNonInterference({ bundle: codex, boundary, rootDir: source, producer: { name: "Fixture", kind: "test", runtime: "node" }, generatedAt: "2026-10-29T12:04:00.000Z" });
    const claudeWitnessPath = path.join(artifactRoot, "claude.witness.json");
    const codexWitnessPath = path.join(artifactRoot, "codex.witness.json");
    const claudeProofGraphPath = path.join(artifactRoot, "claude.proof-graph.json");
    const codexProofGraphPath = path.join(artifactRoot, "codex.proof-graph.json");
    writeNonInterferenceWitness(claudeWitnessPath, claudeWitnessEnvelope);
    writeNonInterferenceWitness(codexWitnessPath, codexWitnessEnvelope);
    const extraProofGates = subjectOnlyGate ? [{ id: "gate:subject-only", mandatory: false }] : [];
    fs.writeFileSync(claudeProofGraphPath, JSON.stringify(proofGraph(claude, { payload: claudeWitnessEnvelope.payload }, extraProofGates)));
    fs.writeFileSync(codexProofGraphPath, JSON.stringify(proofGraph(codex, { payload: codexWitnessEnvelope.payload }, extraProofGates)));
    cliCandidates = [
      { bundlePath: claudePath, requirementIds: ["SRC-CLAUDE"], mappings: { "SRC-CLAUDE": "R-CLAUDE" }, witnessFile: claudeWitnessPath, boundaryManifest: boundaryPath, proofGraph: claudeProofGraphPath, root: source },
      { bundlePath: codexPath, requirementIds: ["SRC-CODEX"], mappings: { "SRC-CODEX": "R-CODEX" }, witnessFile: codexWitnessPath, boundaryManifest: boundaryPath, proofGraph: codexProofGraphPath, root: source },
    ];
    assert.equal(verifyBundleNonInterference(claudeWitnessEnvelope, { bundle: claude, boundary, rootDir: source }).semanticProof, true);
    assert.equal(verifyBundleNonInterference(codexWitnessEnvelope, { bundle: codex, boundary, rootDir: source }).semanticProof, true);
  }
  return { source, sourceMission, target, targetMission, candidates, cliCandidates, claudeTargetPath };
}

function options(context, overrides = {}) {
  return {
    missionDir: context.targetMission,
    candidates: context.candidates,
    gates: [
      { id: "gate:selected", command: [process.execPath, "-e", `process.exit(require('fs').existsSync(${JSON.stringify(context.claudeTargetPath)}) ? 0 : 9)`], mandatory: false },
      { id: "gate:mandatory", command: [process.execPath, "-e", "process.exit(require('fs').existsSync('candidate/codex.txt') ? 0 : 8)"], mandatory: true },
    ],
    actor: { name: "Operator", kind: "human", runtime: "test" },
    generatedAt: "2026-10-29T12:05:00.000Z",
    ...overrides,
  };
}

function snapshot(context) {
  return {
    head: git(context.target, ["rev-parse", "HEAD"]),
    tree: git(context.target, ["rev-parse", "HEAD^{tree}"]),
    status: git(context.target, ["status", "--porcelain=v1", "--untracked-files=all"]),
    events: fs.readFileSync(path.join(context.targetMission, "events.jsonl"), "utf8"),
    worktrees: git(context.target, ["worktree", "list", "--porcelain"]),
  };
}

function rollbackAdmission() {
  const boundary = createBoundaryManifest({
    id: "manifest:composition-rollback",
    generatedAt: "2026-10-29T12:04:30.000Z",
    disclosure: "internal",
    sources: [],
    components: [{ id: "component:candidate", owner: "team:test", disclosure: "internal", paths: ["candidate/**"], requirementIds: ["R-CLAUDE", "R-CODEX"], dependencies: [], interfaces: [], invariantIds: ["invariant:rollback"], gateIds: ["gate:rollback"] }],
    invariants: [{ id: "invariant:rollback", kind: "behavior", description: "Composition candidate bytes must be reversibly applied.", subjectIds: ["component:candidate"], gateIds: ["gate:rollback"] }],
    gates: [{ id: "gate:rollback", kind: "release", description: "Require repository-backed rollback equivalence.", subjectIds: ["component:candidate"], mandatory: true }],
  });
  const policyBody = { id: "policy:composition-rollback", requiredStatus: "equivalent" };
  const policy = { ...policyBody, digest: `sha256:${sha256(canonicalJson(policyBody))}` };
  return { required: true, boundary, policy, runtimeEffects: [] };
}

test("plans both Claude/Codex orders, proves an equal observable tree, and reruns invalidated plus mandatory gates", () => {
  const context = fixture();
  assert.equal(Object.hasOwn(readState(context.targetMission), "compositions"), false, "legacy snapshots remain stable until the first composition event");
  const before = snapshot(context);
  const result = planComposition(options(context));
  assert.equal(result.certificate.payload.verdict, "ready");
  assert.deepEqual(result.certificate.payload.body.orders.map((item) => item.order), [
    ["B-CLAUDE", "B-CODEX"],
    ["B-CODEX", "B-CLAUDE"],
  ]);
  assert.equal(new Set(result.certificate.payload.body.orders.map((item) => item.observableTreeDigest)).size, 1);
  assert.deepEqual(result.certificate.payload.body.gates.map((item) => item.id), ["gate:mandatory", "gate:selected"]);
  assert.deepEqual(result.resourceUsage, {
    validOrderCount: 2,
    peakConcurrentWorktrees: 1,
    applicationOperationsPerOrder: 2,
    plannedApplicationOperations: 4,
    maxApplicationOperations: 10_000,
  });
  assert.equal(verifyCompositionCertificate(result.certificate).verified, true);
  const repeated = planComposition(options(context));
  assert.equal(repeated.certificate.digest, result.certificate.digest, "hermetic Git produces the same composition proof on rerun");
  assert.deepEqual(snapshot(context), before);
});

test("rollback-required composition binds exact repository-backed evidence into authorization and mission history", () => {
  const context = fixture();
  const result = composeBundles(options(context, { rollbackAdmission: rollbackAdmission() }));
  const evidence = result.compositionCertificate.payload.body.rollbackEvidence;
  assert.equal(result.compositionCertificate.payload.body.rollbackRequired, true);
  assert.equal(evidence.status, "equivalent");
  assert.equal(evidence.baseHead, result.baseHead);
  assert.equal(evidence.forwardTip, result.compositionCertificate.payload.body.orders.find((item) => canonicalJson(item.order) === canonicalJson(result.canonicalOrder)).head);
  assert.equal(verifyCompositionCertificate(result.compositionCertificate, { repository: context.target }).verified, true);
  assert.throws(() => verifyCompositionCertificate(result.compositionCertificate), /exact local repository/i);
  assert.equal(verifyMergeCertificate(result.mergeCertificate, { compositionCertificate: result.compositionCertificate, repository: context.target }).verified, true);
  const state = readState(context.targetMission);
  assert.equal(state.compositions.at(-1).rollbackEvidence.digest, evidence.digest);
  assert.equal(state.compositions.at(-1).rollbackEvidence.status, "equivalent");
});

test("five independent candidates prove all 120 orders with constant disposable-worktree usage", { timeout: 180_000 }, () => {
  const context = fixture({ candidateCount: 5 });
  const before = snapshot(context);
  const result = planComposition(options(context));
  assert.equal(result.certificate.payload.body.orders.length, 120);
  assert.deepEqual(result.resourceUsage, {
    validOrderCount: 120,
    peakConcurrentWorktrees: 1,
    applicationOperationsPerOrder: 5,
    plannedApplicationOperations: 600,
    maxApplicationOperations: 10_000,
  });
  assert.equal(new Set(result.certificate.payload.body.orders.map((item) => item.observableTreeDigest)).size, 1);
  assert.deepEqual(snapshot(context), before);
});

test("security and release gates cannot be pruned even when not marked mandatory", () => {
  const context = fixture();
  const pass = [process.execPath, "-e", "process.exit(0)"];
  const result = planComposition(options(context, {
    gates: [
      { id: "gate:ordinary", command: pass, mandatory: false, kind: "test" },
      { id: "gate:security", command: pass, mandatory: false, kind: "security" },
      { id: "gate:release", command: pass, mandatory: false, kind: "release" },
      { id: "gate:mandatory", command: pass, mandatory: true, kind: "test" },
      { id: "gate:selected", command: pass, mandatory: false, kind: "test" },
    ],
  }));
  assert.deepEqual(result.certificate.payload.body.gates.map((item) => item.id), ["gate:mandatory", "gate:release", "gate:security", "gate:selected"]);
});

test("boundary-policy gates cannot be omitted from a caller-authored invalidation graph", () => {
  const context = fixture();
  for (const candidate of context.candidates) {
    candidate.proofGraph.nodes = candidate.proofGraph.nodes.filter((node) => node.id !== "gate:selected");
    candidate.proofGraph.edges = candidate.proofGraph.edges.filter((edge) => edge.to !== "gate:selected" && edge.from !== "gate:selected");
  }
  assert.throws(() => planComposition(options(context)), /cover every.*boundary-policy gate|gate exactly once/i);

  const edgeOmission = fixture();
  for (const candidate of edgeOmission.candidates) candidate.proofGraph.edges = [];
  assert.throws(() => planComposition(options(edgeOmission)), /omits a required.*policy-gate path/i);
});

test("verified boundary mandatory-gate semantics cannot be downgraded in the graph or command", () => {
  const graphDowngrade = fixture();
  for (const candidate of graphDowngrade.candidates) candidate.proofGraph.nodes.find((node) => node.id === "gate:mandatory").mandatory = false;
  assert.throws(() => planComposition(options(graphDowngrade)), /changed.*mandatory semantics/i);

  const commandDowngrade = fixture();
  const gates = options(commandDowngrade).gates.map((gate) => gate.id === "gate:mandatory" ? { ...gate, mandatory: false } : gate);
  assert.throws(() => planComposition(options(commandDowngrade, { gates })), /changed.*mandatory semantics/i);
});

test("required semantic analyzers are complete and recomputed from exact target-context bytes", () => {
  const accepted = fixture({ semanticSql: true });
  const planned = planComposition(options(accepted));
  assert.equal(planned.certificate.payload.body.proofBasis.analyzerCoverageComplete, true);
  assert.match(planned.certificate.payload.body.analyzerCoverageDigest, /^sha256:[0-9a-f]{64}$/u);

  const missing = fixture({ semanticSql: true });
  missing.candidates[0].analyzerReports = [];
  assert.throws(() => planComposition(options(missing)), /missing required sql analyzer evidence/i);

  const forged = fixture({ semanticSql: true });
  const fabricated = structuredClone(forged.candidates[0].analyzerReports[0]);
  fabricated.effects = [];
  const { digest: ignored, ...fabricatedBody } = fabricated;
  assert.ok(ignored);
  fabricated.digest = `sha256:${sha256(canonicalJson(fabricatedBody))}`;
  forged.candidates[0].analyzerReports = [fabricated];
  assert.throws(() => planComposition(options(forged)), /does not match deterministic.*recomputation/i);

  const renamed = fixture({ renameSql: true });
  const renamePlan = planComposition(options(renamed));
  assert.equal(renamePlan.certificate.payload.body.proofBasis.analyzerCoverageComplete, true);
  const wrongTransition = structuredClone(renamed.candidates[0].analyzerReports[0]);
  wrongTransition.subject.before.path = wrongTransition.subject.after.path;
  wrongTransition.requestDigest = `sha256:${sha256(canonicalJson({ analyzer: wrongTransition.analyzer.id, before: wrongTransition.subject.before, after: wrongTransition.subject.after }))}`;
  const { digest: ignoredRenameDigest, ...wrongTransitionBody } = wrongTransition;
  assert.ok(ignoredRenameDigest);
  wrongTransition.digest = `sha256:${sha256(canonicalJson(wrongTransitionBody))}`;
  renamed.candidates[0].analyzerReports = [wrongTransition];
  assert.throws(() => planComposition(options(renamed)), /exact changed-path transition|stale for the target/i);
});

test("composition rejects partial selection of a certified bundle instead of laundering full-bundle proof", () => {
  const context = fixture({ multiRequirementClaude: true });
  assert.throws(() => planComposition(options(context)), /complete certified selection|selective promotion/i);
});

test("a bundle already applied through selective promotion cannot be composed again", () => {
  const context = fixture();
  const bundle = readBundle(context.candidates[0].bundlePath);
  const actor = { name: "Operator", kind: "human", runtime: "test" };
  appendEvent(context.targetMission, {
    type: "BUNDLE_IMPORTED",
    actor,
    payload: {
      bundleId: bundle.payload.id,
      digest: bundle.digest,
      source: bundle.payload.source,
      requirementIds: ["SRC-CLAUDE"],
      dependencies: [],
      commits: [],
      components: [],
      evidence: [],
    },
  }, { reducer: missionReducer, currentHead: git(context.target, ["rev-parse", "HEAD"]) });
  const promoted = appendEvent(context.targetMission, {
    type: "BUNDLE_PROMOTED",
    actor,
    payload: {
      bundleId: bundle.payload.id,
      digest: bundle.digest,
      sourceRequirementIds: ["SRC-CLAUDE"],
      targetRequirementIds: ["R-CLAUDE"],
      mappings: { "SRC-CLAUDE": "R-CLAUDE" },
      appliedCommits: [],
      components: [],
      reusableEvidence: [],
      expiredEvidence: [],
    },
  }, { reducer: missionReducer, currentHead: git(context.target, ["rev-parse", "HEAD"]) });
  renderMission(context.targetMission, promoted.state);
  commit(context.target, "record prior selective promotion");
  assert.throws(() => planComposition(options(context)), /already (?:promoted|composed)/i);
});

test("successful execution fast-forwards exactly once, records one composition event, and emits offline-verifiable certificates", () => {
  const context = fixture();
  const before = snapshot(context);
  const stateBefore = readState(context.targetMission);
  const reflogBefore = git(context.target, ["reflog", "--format=%H"]).split("\n").filter(Boolean).length;
  const result = composeBundles(options(context));
  assert.notEqual(result.head, before.head);
  assert.equal(git(context.target, ["rev-parse", "HEAD"]), result.head);
  assert.equal(fs.readFileSync(path.join(context.target, "candidate", "claude.txt"), "utf8"), "claude result\n");
  assert.equal(fs.readFileSync(path.join(context.target, "candidate", "codex.txt"), "utf8"), "codex result\n");
  assert.equal(verifyCompositionCertificate(result.compositionCertificate).verified, true);
  assert.equal(verifyMergeCertificate(result.mergeCertificate, { compositionCertificate: result.compositionCertificate }).verified, true);
  assert.equal(verifyMergeCertificate(result.mergeCertificate, { compositionCertificate: result.compositionCertificate, repository: context.target }).verified, true);
  const state = readState(context.targetMission);
  assert.equal(state.compositions.length, 1);
  assert.equal(state.audit.filter((item) => item.type === "COMPOSITION_MERGED").length, 1);
  assert.equal(state.requirements["R-CLAUDE"].status, "IN_PROGRESS");
  assert.equal(state.requirements["R-CODEX"].status, "IN_PROGRESS");
  assert.deepEqual(replayEvents(context.targetMission, { reducer: missionReducer }).state, state);
  const history = explainMissionHistory(context.targetMission, { requirementId: "R-CLAUDE" });
  assert.ok(history.causalPath.some((item) => item.type === "COMPOSITION_MERGED"));
  const event = JSON.parse(fs.readFileSync(path.join(context.targetMission, "events.jsonl"), "utf8").trim().split("\n").at(-1));
  assert.throws(() => missionReducer(state, { ...event, id: `${event.id}-smuggled`, payload: { ...event.payload, unsupported: true } }), /unknown.*field/i);
  const smuggledSource = structuredClone(event);
  smuggledSource.payload.candidates[0].source.unsupported = true;
  assert.throws(() => missionReducer(stateBefore, smuggledSource), /unknown.*source.*field/i);
  const escapingComponent = structuredClone(event);
  escapingComponent.payload.candidates[0].components.push({ targetPath: "../escape", digest: `sha256:${"0".repeat(64)}`, type: "file", status: "applied" });
  assert.throws(() => missionReducer(stateBefore, escapingComponent), /portable|path|unsafe/i);
  assert.equal(git(context.target, ["status", "--porcelain=v1", "--untracked-files=all"]), "");
  assert.equal(git(context.target, ["reflog", "--format=%H"]).split("\n").filter(Boolean).length, reflogBefore + 1);
});

test("tampering invalidates composition and merge certificates offline", () => {
  const context = fixture();
  const result = composeBundles(options(context));
  const composition = structuredClone(result.compositionCertificate);
  composition.payload.body.canonicalOrder.reverse();
  assert.throws(() => verifyCompositionCertificate(composition), /digest|tamper/i);
  const merge = structuredClone(result.mergeCertificate);
  merge.payload.body.resultHead = "0".repeat(40);
  assert.throws(() => verifyMergeCertificate(merge, { compositionCertificate: result.compositionCertificate }), /digest|tamper/i);
  const wrongTreeDigestPayload = structuredClone(result.mergeCertificate.payload);
  wrongTreeDigestPayload.body.resultTreeDigest = `sha256:${"0".repeat(64)}`;
  wrongTreeDigestPayload.subjects[0].digest = wrongTreeDigestPayload.body.resultTreeDigest;
  const wrongTreeDigest = createCertifiedEnvelope({ format: result.mergeCertificate.format, payload: wrongTreeDigestPayload });
  assert.throws(() => verifyMergeCertificate(wrongTreeDigest, { compositionCertificate: result.compositionCertificate }), /resultTreeDigest|result tree object/i);
  const arbitraryProofPayload = structuredClone(result.mergeCertificate.payload);
  arbitraryProofPayload.body.proofGraphDigest = `sha256:${"f".repeat(64)}`;
  const arbitraryProof = createCertifiedEnvelope({ format: result.mergeCertificate.format, payload: arbitraryProofPayload });
  assert.throws(() => verifyMergeCertificate(arbitraryProof, { compositionCertificate: result.compositionCertificate }), /proofGraphDigest|exact admitted composition proof/i);

  const forgedPairPayload = structuredClone(result.compositionCertificate.payload);
  const pair = forgedPairPayload.body.pairwiseMatrix[0];
  pair.requiredOrder = [pair.leftBundleId, pair.rightBundleId];
  pair.commutes = false;
  const forgedPair = createCertifiedEnvelope({ format: result.compositionCertificate.format, payload: forgedPairPayload });
  assert.throws(() => verifyCompositionCertificate(forgedPair), /ordering.*dependency graph/i);

  const missingFootprintPayload = structuredClone(result.compositionCertificate.payload);
  const omittedBundle = missingFootprintPayload.body.candidateDigests[0].id;
  missingFootprintPayload.body.composedFootprint = missingFootprintPayload.body.composedFootprint.filter((effectRecord) => effectRecord.bundleId !== omittedBundle);
  const missingFootprint = createCertifiedEnvelope({ format: result.compositionCertificate.format, payload: missingFootprintPayload });
  assert.throws(() => verifyCompositionCertificate(missingFootprint), /footprint omits candidate/i);

  const wrongParentPayload = structuredClone(result.mergeCertificate.payload);
  wrongParentPayload.body.resultParentHead = wrongParentPayload.body.baseHead;
  const wrongParent = createCertifiedEnvelope({ format: result.mergeCertificate.format, payload: wrongParentPayload });
  assert.throws(() => verifyMergeCertificate(wrongParent, { compositionCertificate: result.compositionCertificate }), /canonical prepared order|sole parent/i);

  const forgedEventPayload = structuredClone(result.mergeCertificate.payload);
  forgedEventPayload.body.missionEvent.payload.candidates[0].appliedCommits[0].targetSha = "0".repeat(40);
  const { hash: _oldHash, ...unsignedEvent } = forgedEventPayload.body.missionEvent;
  forgedEventPayload.body.missionEvent.hash = sha256(canonicalJson(unsignedEvent));
  const forgedEvent = createCertifiedEnvelope({ format: result.mergeCertificate.format, payload: forgedEventPayload });
  assert.throws(() => verifyMergeCertificate(forgedEvent, { compositionCertificate: result.compositionCertificate }), /canonical commit.*applications|missionEvent/i);

  const forgedCommitPayload = structuredClone(result.mergeCertificate.payload);
  const rawCommit = Buffer.from(forgedCommitPayload.body.gitObjectProof.commit.content, "base64");
  forgedCommitPayload.body.gitObjectProof.commit.content = Buffer.concat([rawCommit, Buffer.from("forged\n")]).toString("base64");
  const forgedCommit = createCertifiedEnvelope({ format: result.mergeCertificate.format, payload: forgedCommitPayload });
  assert.throws(() => verifyMergeCertificate(forgedCommit, { compositionCertificate: result.compositionCertificate }), /does not hash|object ID/i);
});

test("composition and merge certificates use the shared strict certified-envelope kernel", () => {
  const context = fixture();
  const result = composeBundles(options(context));
  assert.equal(result.compositionCertificate.schemaVersion, 1);
  assert.equal(result.compositionCertificate.format, "tugboat.composition-certificate.v1");
  assert.equal(result.mergeCertificate.format, "tugboat.merge-certificate.v1");
  const confused = structuredClone(result.compositionCertificate);
  confused.format = "tugboat.merge-certificate.v1";
  assert.throws(() => verifyCompositionCertificate(confused), /format|digest/i);
  const unknown = { ...result.compositionCertificate, signature: { value: "invented" } };
  assert.throws(() => verifyCompositionCertificate(unknown), /unknown.*field/i);
  const forgedPayload = structuredClone(result.compositionCertificate.payload);
  forgedPayload.body.proofBasis.orderCount = 0;
  const structurallyValidForgery = createCertifiedEnvelope({ format: result.compositionCertificate.format, payload: forgedPayload });
  assert.throws(() => verifyCompositionCertificate(structurallyValidForgery), /proofBasis|orderCount/i);
  const failedClaimPayload = structuredClone(result.compositionCertificate.payload);
  failedClaimPayload.claims[0].status = "failed";
  const failedClaim = createCertifiedEnvelope({ format: result.compositionCertificate.format, payload: failedClaimPayload });
  assert.throws(() => verifyCompositionCertificate(failedClaim), /passed claim|counterexamples/i);
  const confusedKindPayload = structuredClone(result.compositionCertificate.payload);
  confusedKindPayload.subjects[0].kind = "artifact";
  const confusedKind = createCertifiedEnvelope({ format: result.compositionCertificate.format, payload: confusedKindPayload });
  assert.throws(() => verifyCompositionCertificate(confusedKind), /subjects and inputs|not bound/i);
  assert.throws(() => verifyMergeCertificate(result.mergeCertificate), /requires.*composition certificate/i);
});

test("certificate artifacts are emitted atomically outside the target and never overwrite evidence", () => {
  const context = fixture();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-artifacts-"));
  const compositionCertificatePath = path.join(root, "composition.json");
  const mergeCertificatePath = path.join(root, "merge.json");
  const originalFsync = fs.fsyncSync;
  let directorySyncs = 0;
  fs.fsyncSync = (descriptor) => {
    if (fs.fstatSync(descriptor).isDirectory()) directorySyncs += 1;
    return originalFsync(descriptor);
  };
  let result;
  try {
    result = composeBundles(options(context, { compositionCertificatePath, mergeCertificatePath }));
  } finally {
    fs.fsyncSync = originalFsync;
  }
  assert.ok(directorySyncs >= 4, `expected staging and publication directory fsyncs, received ${directorySyncs}`);
  assert.equal(result.evidenceEmission.status, "complete");
  assert.equal(verifyCompositionCertificate(JSON.parse(fs.readFileSync(compositionCertificatePath, "utf8"))).digest, result.compositionCertificate.digest);
  assert.equal(verifyMergeCertificate(JSON.parse(fs.readFileSync(mergeCertificatePath, "utf8")), { compositionCertificate: result.compositionCertificate }).digest, result.mergeCertificate.digest);

  const blocked = fixture();
  const before = snapshot(blocked);
  assert.throws(() => planComposition(options(blocked, { compositionCertificatePath: path.join(blocked.target, "certificate.json") })), /outside.*target|dirty/i);
  assert.throws(() => planComposition(options(blocked, { compositionCertificatePath: path.join(blocked.target, "..evidence", "certificate.json") })), /outside.*target/i);
  assert.deepEqual(snapshot(blocked), before);
  const existing = path.join(root, "existing.json");
  fs.writeFileSync(existing, "keep\n");
  assert.throws(() => planComposition(options(blocked, { compositionCertificatePath: existing })), /already exists|overwrite/i);
  assert.equal(fs.readFileSync(existing, "utf8"), "keep\n");
  const aliasRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-alias-"));
  const targetAlias = path.join(aliasRoot, "target-alias");
  fs.symlinkSync(blocked.target, targetAlias, "dir");
  assert.throws(() => planComposition(options(blocked, { compositionCertificatePath: path.join(targetAlias, "aliased-certificate.json") })), /outside.*target/i);
  assert.deepEqual(snapshot(blocked), before);

  const unwritable = fixture();
  const unwritableBefore = snapshot(unwritable);
  assert.throws(() => composeBundles(options(unwritable, {
    compositionCertificatePath: path.join("/dev/null", "composition.json"),
    mergeCertificatePath: path.join(root, "never-published-merge.json"),
  })), /stage certificate|not a directory|ENOTDIR/i);
  assert.deepEqual(snapshot(unwritable), unwritableBefore);
});

test("a cleanup failure after successful advancement returns complete recovery evidence", () => {
  const context = fixture();
  const originalRemove = fs.rmSync;
  let failedRoot;
  fs.rmSync = (target, removeOptions) => {
    if (!failedRoot && path.basename(String(target)).startsWith("tugboat-compose-")) {
      failedRoot = String(target);
      throw new Error("forced cleanup durability test");
    }
    return originalRemove(target, removeOptions);
  };
  let result;
  try {
    result = composeBundles(options(context));
  } finally {
    fs.rmSync = originalRemove;
  }
  assert.equal(result.status, "recovery_required");
  assert.equal(result.evidenceEmission.status, "recovery_required");
  assert.match(result.evidenceEmission.reason, /cleanup needs operator recovery/i);
  assert.ok(result.evidenceEmission.cleanupFailures.some((item) => /forced cleanup durability test|temporary root still exists/i.test(item)));
  assert.equal(git(context.target, ["rev-parse", "HEAD"]), result.head);
  assert.equal(readState(context.targetMission).compositions.length, 1);
  assert.ok(failedRoot && fs.existsSync(failedRoot));
  originalRemove(failedRoot, { recursive: true, force: true });
});

test("partial patch application blocks without target mutation and cleans disposable worktrees", () => {
  const context = fixture({ divergent: true });
  const before = snapshot(context);
  let failure;
  try { planComposition(options(context)); } catch (error) { failure = error; }
  assert.match(failure.message, /order|apply|conflict|diverge/i);
  assert.equal(failure.details.counterexample.code, "order_application_failed");
  assert.deepEqual(snapshot(context), before);
});

test("order-dependent repository semantics block divergent observable trees without target mutation", () => {
  const context = fixture({ orderDivergent: true });
  const before = snapshot(context);
  let failure;
  try { planComposition(options(context)); } catch (error) { failure = error; }
  assert.match(failure.message, /orders? diverge|diverge.*observable/i);
  assert.equal(failure.details.counterexample.code, "order_divergence");
  assert.equal(new Set(failure.details.counterexample.actual.map((item) => item.observableTreeDigest)).size, 2);
  assert.deepEqual(snapshot(context), before);
});

test("composition rejects executable repository Git drivers and filters instead of inheriting ambient behavior", () => {
  const context = fixture();
  const marker = path.join(context.target, "filter-ran.marker");
  git(context.target, ["config", "filter.untrusted.clean", `${process.execPath} -e require('fs').writeFileSync(${JSON.stringify(marker)},'ran')`]);
  const before = snapshot(context);
  assert.throws(() => planComposition(options(context)), /executable or ambient Git configuration|filter\.untrusted\.clean/i);
  assert.equal(fs.existsSync(marker), false);
  assert.deepEqual(snapshot(context), before);
});

test("composition rejects ambient Git application settings and untracked repository attributes", () => {
  const configured = fixture();
  git(configured.target, ["config", "apply.whitespace", "nowarn"]);
  const configuredBefore = snapshot(configured);
  assert.throws(() => planComposition(options(configured)), /ambient Git configuration|apply\.whitespace/i);
  assert.deepEqual(snapshot(configured), configuredBefore);

  const sparse = fixture();
  git(sparse.target, ["config", "core.sparseCheckout", "true"]);
  const sparseBefore = snapshot(sparse);
  assert.throws(() => planComposition(options(sparse)), /ambient Git configuration|core\.sparsecheckout/i);
  assert.deepEqual(snapshot(sparse), sparseBefore);

  const scissors = fixture();
  git(scissors.target, ["config", "mailinfo.scissors", "true"]);
  const scissorsBefore = snapshot(scissors);
  assert.throws(() => planComposition(options(scissors)), /ambient Git configuration|mailinfo\.scissors/i);
  assert.deepEqual(snapshot(scissors), scissorsBefore);

  const attributed = fixture();
  const attributesPath = git(attributed.target, ["rev-parse", "--git-path", "info/attributes"]);
  const absoluteAttributes = path.resolve(attributed.target, attributesPath);
  fs.mkdirSync(path.dirname(absoluteAttributes), { recursive: true });
  fs.writeFileSync(absoluteAttributes, "stable.txt -text\n");
  const attributedBefore = snapshot(attributed);
  assert.throws(() => planComposition(options(attributed)), /ambient \.git\/info\/attributes|content-addressed tracked attributes/i);
  assert.deepEqual(snapshot(attributed), attributedBefore);
});

test("composition rejects plans whose exhaustive application count exceeds the operation budget", () => {
  const context = fixture({ candidateCount: 5 });
  const first = context.candidates[0];
  const envelope = JSON.parse(fs.readFileSync(first.bundlePath, "utf8"));
  const extraEffects = [];
  for (let index = 0; index < 79; index += 1) {
    const targetPath = `candidate/budget-${index}.txt`;
    const contents = Buffer.from(`budget ${index}\n`);
    envelope.payload.components.push({
      type: "code",
      label: `Budget ${index}`,
      sourcePath: `fixture/budget-${index}.txt`,
      targetPath,
      requirementIds: ["SRC-CLAUDE"],
      encoding: "base64",
      size: contents.length,
      digest: `sha256:${sha256(contents)}`,
      content: contents.toString("base64"),
    });
    extraEffects.push(effect(`effect:budget-${index}`, targetPath));
  }
  envelope.digest = `sha256:${sha256(canonicalJson(envelope.payload))}`;
  fs.writeFileSync(first.bundlePath, `${canonicalJson(envelope)}\n`);
  const updatedBundle = readBundle(first.bundlePath);
  first.witness = witness(updatedBundle, [...first.witness.payload.body.effects, ...extraEffects]);
  first.proofGraph = proofGraph(updatedBundle, first.witness);
  const before = snapshot(context);
  let failure;
  try { planComposition(options(context)); } catch (error) { failure = error; }
  assert.match(failure?.message ?? "", /10080 application operations|10000 operation budget/i);
  assert.deepEqual(failure.details.resourceUsage, {
    validOrderCount: 120,
    applicationOperationsPerOrder: 84,
    plannedApplicationOperations: 10_080,
    maxApplicationOperations: 10_000,
  });
  assert.deepEqual(snapshot(context), before);
});

test("validation mutation and validation failure are fail-closed", () => {
  const dirty = fixture();
  const dirtyBefore = snapshot(dirty);
  assert.throws(() => composeBundles(options(dirty, {
    gates: [
      { id: "gate:dirty", command: [process.execPath, "-e", "require('fs').writeFileSync('generated.tmp','dirty')"], mandatory: true },
      ...options(dirty).gates,
    ],
  })), /gate.*dirty|uncommitted|mutation/i);
  assert.deepEqual(snapshot(dirty), dirtyBefore);

  const failed = fixture();
  const failedBefore = snapshot(failed);
  assert.throws(() => composeBundles(options(failed, {
    gates: [
      { id: "gate:fail", command: [process.execPath, "-e", "process.exit(17)"], mandatory: true },
      ...options(failed).gates,
    ],
  })), /gate.*17|exit.*17/i);
  assert.deepEqual(snapshot(failed), failedBefore);

  const committed = fixture();
  const committedBefore = snapshot(committed);
  const commitMutation = [process.execPath, "-e", "const fs=require('fs');const {execFileSync}=require('child_process');fs.writeFileSync('committed.tmp','mutation');execFileSync('git',['add','committed.tmp']);execFileSync('git',['commit','-m','validation mutation'])"];
  assert.throws(() => composeBundles(options(committed, {
    gates: [
      { id: "gate:commit", command: commitMutation, mandatory: true },
      ...options(committed).gates,
    ],
  })), /committed|rewrote|history.*mutation/i);
  assert.deepEqual(snapshot(committed), committedBefore);
});

test("dirty targets and final target drift block before any composition event", () => {
  const dirty = fixture();
  fs.writeFileSync(path.join(dirty.target, "local.tmp"), "dirty\n");
  const dirtyEvents = fs.readFileSync(path.join(dirty.targetMission, "events.jsonl"), "utf8");
  assert.throws(() => planComposition(options(dirty)), /dirty|clean/i);
  assert.equal(fs.readFileSync(path.join(dirty.targetMission, "events.jsonl"), "utf8"), dirtyEvents);

  const drift = fixture();
  const originalEvents = fs.readFileSync(path.join(drift.targetMission, "events.jsonl"), "utf8");
  const mutateTarget = [process.execPath, "-e", `const {execFileSync}=require('node:child_process');execFileSync('git',['commit','--allow-empty','-m','concurrent drift'],{cwd:${JSON.stringify(drift.target)}})`];
  assert.throws(() => composeBundles(options(drift, {
    gates: [
      { id: "gate:drift", command: mutateTarget, mandatory: true },
      ...options(drift).gates,
    ],
  })), /target.*changed|stale|drift/i);
  assert.equal(fs.readFileSync(path.join(drift.targetMission, "events.jsonl"), "utf8"), originalEvents);
  assert.equal((readState(drift.targetMission).compositions ?? []).length, 0);
});

test("a symlinked mission path is rejected before external ledger mutation", () => {
  const context = fixture();
  const externalRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-external-mission-"));
  const externalMission = path.join(externalRoot, "mission");
  fs.cpSync(context.targetMission, externalMission, { recursive: true });
  fs.rmSync(context.targetMission, { recursive: true });
  fs.symlinkSync(externalMission, context.targetMission, "dir");
  commit(context.target, "replace mission path with external symlink");
  const externalEvents = fs.readFileSync(path.join(externalMission, "events.jsonl"), "utf8");
  const externalState = fs.readFileSync(path.join(externalMission, "state.json"), "utf8");
  assert.throws(() => planComposition(options(context)), /mission path.*symbolic link|resolve inside/i);
  assert.equal(fs.readFileSync(path.join(externalMission, "events.jsonl"), "utf8"), externalEvents);
  assert.equal(fs.readFileSync(path.join(externalMission, "state.json"), "utf8"), externalState);

  const fileLink = fixture();
  const externalEventsFile = path.join(externalRoot, "external-events.jsonl");
  const originalEvents = fs.readFileSync(path.join(fileLink.targetMission, "events.jsonl"), "utf8");
  fs.writeFileSync(externalEventsFile, originalEvents);
  fs.rmSync(path.join(fileLink.targetMission, "events.jsonl"));
  fs.symlinkSync(externalEventsFile, path.join(fileLink.targetMission, "events.jsonl"));
  commit(fileLink.target, "replace canonical event log with external symlink");
  assert.throws(() => planComposition(options(fileLink)), /canonical mission path.*symbolic link/i);
  assert.equal(fs.readFileSync(externalEventsFile, "utf8"), originalEvents);
});

test("dependency-constrained compositions evaluate only valid order and still require fast-forward ancestry", () => {
  const context = fixture({ dependent: true });
  const planned = planComposition(options(context));
  assert.deepEqual(planned.certificate.payload.body.orders.map((item) => item.order), [["B-CLAUDE", "B-CODEX"]]);
  const result = composeBundles(options(context));
  assert.equal(git(context.target, ["merge-base", "--is-ancestor", result.baseHead, result.head]), "");
  assert.deepEqual(result.compositionCertificate.payload.body.canonicalOrder, ["B-CLAUDE", "B-CODEX"]);
});

test("portable CLI prepares, applies, emits, and offline-verifies a real composition", () => {
  const context = fixture({ withCli: true });
  const before = snapshot(context);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-cli-"));
  const manifest = path.join(root, "composition.json");
  fs.writeFileSync(manifest, JSON.stringify({
    candidates: context.cliCandidates,
    gates: options(context).gates,
    generatedAt: "2026-10-29T12:06:00.000Z",
  }));
  const cli = path.resolve("scripts/tugboat.mjs");
  const planned = JSON.parse(execFileSync(process.execPath, [cli, "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--dry-run", "--json"], { encoding: "utf8" }));
  assert.equal(planned.certificate.payload.verdict, "ready");
  const certificatePath = path.join(root, "composition-certificate.json");
  fs.writeFileSync(certificatePath, JSON.stringify(planned.certificate));
  const verified = JSON.parse(execFileSync(process.execPath, [cli, "certificate", "verify-composition", "--file", certificatePath, "--json"], { encoding: "utf8" }));
  assert.equal(verified.verified, true);
  let missingOutputFailure;
  try {
    execFileSync(process.execPath, [cli, "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--apply", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    missingOutputFailure = error;
  }
  assert.match(missingOutputFailure?.stderr?.toString() ?? "", /requires.*composition-certificate.*merge-certificate/i);
  assert.deepEqual(snapshot(context), before);
  const witnessPath = context.cliCandidates[0].witnessFile;
  const originalWitness = fs.readFileSync(witnessPath, "utf8");
  const tampered = JSON.parse(originalWitness);
  tampered.payload.body.bundleDigest = `sha256:${"0".repeat(64)}`;
  fs.writeFileSync(witnessPath, JSON.stringify(tampered));
  let witnessFailure;
  try {
    execFileSync(process.execPath, [cli, "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--dry-run", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    witnessFailure = error;
  }
  const structuredFailure = JSON.parse(witnessFailure?.stderr?.toString() ?? "{}");
  assert.match(structuredFailure.message ?? "", /digest mismatch|semantic mismatch|stale/i);
  assert.equal(Number.isInteger(structuredFailure.exitCode), true);
  assert.equal(typeof structuredFailure.error, "string");
  assert.deepEqual(snapshot(context), before);
  fs.writeFileSync(witnessPath, originalWitness);
  const emittedCompositionPath = path.join(root, "emitted-composition.json");
  const emittedMergePath = path.join(root, "emitted-merge.json");
  const applied = JSON.parse(execFileSync(process.execPath, [
    cli, "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--apply",
    "--composition-certificate", emittedCompositionPath, "--merge-certificate", emittedMergePath, "--json",
  ], { encoding: "utf8" }));
  assert.equal(applied.dryRun, false);
  assert.equal(git(context.target, ["rev-parse", "HEAD"]), applied.head);
  const mergeVerified = JSON.parse(execFileSync(process.execPath, [
    cli, "certificate", "verify-merge", "--file", emittedMergePath, "--composition", emittedCompositionPath, "--json",
  ], { encoding: "utf8" }));
  assert.equal(mergeVerified.verified, true);
  const repositoryVerified = JSON.parse(execFileSync(process.execPath, [
    cli, "certificate", "verify-merge", "--file", emittedMergePath, "--composition", emittedCompositionPath, "--repository", context.target, "--json",
  ], { encoding: "utf8" }));
  assert.equal(repositoryVerified.verified, true);
  assert.equal(readState(context.targetMission).compositions.length, 1);
});

test("CLI JSON failures preserve machine-readable composition counterexamples", () => {
  const context = fixture({ withCli: true });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-cli-counterexample-"));
  const manifest = path.join(root, "composition.json");
  const mutateTarget = [process.execPath, "-e", `require('node:child_process').execFileSync('git',['commit','--allow-empty','-m','concurrent drift'],{cwd:${JSON.stringify(context.target)}})`];
  fs.writeFileSync(manifest, JSON.stringify({
    candidates: context.cliCandidates,
    gates: [{ id: "gate:drift", command: mutateTarget, mandatory: true }, ...options(context).gates],
    generatedAt: "2026-10-29T12:06:00.000Z",
  }));
  let failure;
  try {
    execFileSync(process.execPath, [path.resolve("scripts/tugboat.mjs"), "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--dry-run", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    failure = error;
  }
  const report = JSON.parse(failure?.stderr?.toString() ?? "{}");
  assert.equal(report.error, "CompositionError");
  assert.equal(report.exitCode, 3);
  assert.equal(report.details.counterexample.code, "target_drift");
  assert.ok(Array.isArray(report.details.counterexample.witnessPath));
});

test("CLI exits nonzero with structured recovery evidence when publication races after target advancement", { timeout: 30_000 }, () => {
  const context = fixture({ withCli: true });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-cli-recovery-"));
  const manifest = path.join(root, "composition.json");
  fs.writeFileSync(manifest, JSON.stringify({ candidates: context.cliCandidates, gates: options(context).gates, generatedAt: "2026-10-29T12:06:00.000Z" }));
  const compositionPath = path.join(root, "composition-certificate.json");
  const mergePath = path.join(root, "merge-certificate.json");
  const watcherReady = path.join(root, "watcher.ready");
  const watcher = spawn(process.execPath, ["-e", `
    const fs = require('node:fs');
    const path = require('node:path');
    const dir = ${JSON.stringify(root)};
    const target = ${JSON.stringify(mergePath)};
    fs.writeFileSync(${JSON.stringify(watcherReady)}, 'ready\\n');
    const prefix = path.basename(target) + '.tmp-';
    const deadline = Date.now() + 20000;
    while (Date.now() <= deadline) {
      if (fs.readdirSync(dir).some((name) => name.startsWith(prefix))) {
        fs.writeFileSync(target, 'publication race\\n', { flag: 'wx' });
        process.exit(0);
      }
    }
    process.exit(2);
  `], { stdio: "ignore" });
  const readyDeadline = Date.now() + 5_000;
  while (!fs.existsSync(watcherReady) && Date.now() < readyDeadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  assert.equal(fs.existsSync(watcherReady), true, "publication-race watcher started");
  let failure;
  try {
    execFileSync(process.execPath, [
      path.resolve("scripts/tugboat.mjs"), "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--apply",
      "--composition-certificate", compositionPath, "--merge-certificate", mergePath, "--json",
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    failure = error;
  } finally {
    watcher.kill();
  }
  assert.equal(failure?.status, 5);
  const result = JSON.parse(failure.stdout.toString());
  assert.equal(result.status, "recovery_required");
  assert.equal(result.evidenceEmission.status, "recovery_required");
  assert.equal(git(context.target, ["rev-parse", "HEAD"]), result.head);
  assert.equal(readState(context.targetMission).compositions.length, 1);
  assert.equal(fs.readFileSync(mergePath, "utf8"), "publication race\n");
  assert.ok(result.evidenceEmission.artifacts.some((artifact) => artifact.kind === "merge" && artifact.status === "staged" && fs.existsSync(artifact.recoveryPath)));
});

test("CLI derives invalidation obligations from boundary gate subject links, not only component gate lists", () => {
  const context = fixture({ withCli: true, subjectOnlyGate: true });
  const before = snapshot(context);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tugboat-composition-subject-gate-"));
  const manifest = path.join(root, "composition.json");
  fs.writeFileSync(manifest, JSON.stringify({ candidates: context.cliCandidates, gates: options(context).gates, generatedAt: "2026-10-29T12:06:00.000Z" }));
  let failure;
  try {
    execFileSync(process.execPath, [path.resolve("scripts/tugboat.mjs"), "bundle", "compose", "--dir", context.targetMission, "--manifest", manifest, "--dry-run", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    failure = error;
  }
  assert.match(failure?.stderr?.toString() ?? "", /omits a required.*policy-gate path.*gate:subject-only/i);
  assert.deepEqual(snapshot(context), before);
});
