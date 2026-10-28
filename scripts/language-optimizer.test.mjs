import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CATALOG_VERSION,
  LANGUAGE_CATALOG,
  validateCatalog,
} from "./lib/language-catalog.mjs";
import {
  compileLanguageRecommendation,
  deriveRequirementSignals,
  evaluateCandidates,
  inspectTrackedRepository,
  selectLanguageTopology,
  validateDecisionProfile,
} from "./lib/language-optimizer.mjs";

function stateWith(requirements) {
  return {
    mission: { id: "architecture-test", title: "Architecture test" },
    revision: 3,
    requirements: requirements.map((requirement) => ({
      material: true,
      status: "PENDING",
      acceptance: "",
      ...requirement,
    })),
  };
}

function git(cwd, args) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

test("language catalog is versioned, complete, source-auditable, and data-valid", () => {
  assert.match(CATALOG_VERSION, /^2026-\d{2}-\d{2}$/);
  assert.deepEqual(
    LANGUAGE_CATALOG.map(({ id }) => id),
    ["csharp", "go", "java", "kotlin", "python", "rust", "swift", "typescript"],
  );
  assert.equal(validateCatalog(), true);
  for (const language of LANGUAGE_CATALOG) {
    assert.match(language.sourceUrl, /^https:\/\//);
    assert.ok(Object.keys(language.capabilities).length >= 4);
    assert.ok(language.evidence.length >= 20);
    assert.equal(Object.isFrozen(language), true);
    assert.equal(Object.isFrozen(language.capabilities), true);
  }

  assert.throws(
    () => validateCatalog([...LANGUAGE_CATALOG, LANGUAGE_CATALOG[0]]),
    /duplicate language id csharp/,
  );
  assert.throws(
    () => validateCatalog([{ ...LANGUAGE_CATALOG[0], capabilities: { invented_signal: 5 } }]),
    /unknown capability invented_signal/,
  );
  assert.throws(
    () => validateCatalog([{ ...LANGUAGE_CATALOG[0], capabilities: { browser_ui: 7 } }]),
    /integer from 0 to 5/,
  );
});

test("explicit profile signals retain requirement-level provenance", () => {
  const state = stateWith([
    { id: "R1", requirement: "Build the operator workflow", acceptance: "Works in production" },
  ]);
  const profile = validateDecisionProfile({
    teamLanguages: ["typescript"],
    maxLanguages: 1,
    requirementSignals: { R1: ["browser_ui", "fast_iteration"] },
  }, state);

  const result = deriveRequirementSignals(state, profile);

  assert.deepEqual(result.unclassifiedRequirementIds, []);
  assert.deepEqual(result.byRequirement.R1, [
    {
      confidence: "explicit",
      excerpt: "profile.requirementSignals.R1",
      ruleId: "profile.requirementSignals",
      signal: "browser_ui",
      source: "profile",
    },
    {
      confidence: "explicit",
      excerpt: "profile.requirementSignals.R1",
      ruleId: "profile.requirementSignals",
      signal: "fast_iteration",
      source: "profile",
    },
  ]);
});

test("conservative inference cites matched ledger excerpts and ignores hype-only language", () => {
  const state = stateWith([
    {
      id: "R1",
      requirement: "Deliver a responsive browser user interface for internal operators.",
      acceptance: "The web application works at desktop and mobile widths.",
    },
    {
      id: "R2",
      requirement: "Build a fast, secure, scalable AI-powered platform.",
      acceptance: "It should be world class.",
    },
    {
      id: "R3",
      requirement: "Run machine-learning model training and dataframe analysis in batch jobs.",
      acceptance: "The data science pipeline is reproducible.",
    },
  ]);

  const result = deriveRequirementSignals(state, validateDecisionProfile({}, state));

  assert.deepEqual(result.byRequirement.R1.map(({ signal }) => signal), ["browser_ui"]);
  assert.match(result.byRequirement.R1[0].excerpt, /browser user interface/i);
  assert.equal(result.byRequirement.R1[0].source, "ledger");
  assert.equal(result.byRequirement.R1[0].confidence, "high");
  assert.deepEqual(result.byRequirement.R2, []);
  assert.deepEqual(result.byRequirement.R3.map(({ signal }) => signal), ["data_ai"]);
  assert.match(result.byRequirement.R3[0].excerpt, /model training/i);
  assert.deepEqual(result.unclassifiedRequirementIds, ["R2"]);
});

test("decision profiles reject unknown, contradictory, unbounded, and secret-bearing input", () => {
  const state = stateWith([{ id: "R1", requirement: "Build it" }]);

  assert.throws(() => validateDecisionProfile({ surprise: true }, state), /unknown profile field surprise/);
  assert.throws(() => validateDecisionProfile({ maxLanguages: 3 }, state), /maxLanguages must be 1 or 2/);
  assert.throws(
    () => validateDecisionProfile({ allowedLanguages: ["typescript"], forbiddenLanguages: ["typescript"] }, state),
    /both allowed and forbidden: typescript/,
  );
  assert.throws(() => validateDecisionProfile({ teamLanguages: ["brainfuck"] }, state), /unknown language brainfuck/);
  assert.throws(
    () => validateDecisionProfile({ requirementSignals: { R9: ["browser_ui"] } }, state),
    /unknown requirement R9/,
  );
  assert.throws(
    () => validateDecisionProfile({ requirementSignals: { R1: ["quantum_magic"] } }, state),
    /unknown signal quantum_magic/,
  );
  assert.throws(
    () => validateDecisionProfile({ priorities: { delivery_speed: 0 } }, state),
    /priority delivery_speed must be an integer from 1 to 5/,
  );
  assert.throws(
    () => validateDecisionProfile({ teamLanguages: [["github", "_pat_", "abcdefghijklmnopqrstuvwxyz123456"].join("")] }, state),
    /contains secret material/,
  );
  assert.throws(
    () => validateDecisionProfile({ teamLanguages: ["typescript"], padding: "x".repeat(70 * 1024) }, state),
    /decision profile exceeds 64 KiB/,
  );
});

test("repository inspection uses only Git-tracked paths and returns stable aggregated facts", () => {
  const repo = mkdtempSync(path.join(os.tmpdir(), "tugboat-language-repo-"));
  git(repo, ["init", "-b", "main"]);
  git(repo, ["config", "user.name", "Tugboat Test"]);
  git(repo, ["config", "user.email", "tugboat@example.invalid"]);
  mkdirSync(path.join(repo, "src"));
  writeFileSync(path.join(repo, "src", "app.ts"), "export const app = true;\n");
  writeFileSync(path.join(repo, "src", "worker.py"), "ready = True\n");
  writeFileSync(path.join(repo, "package.json"), "{}\n");
  writeFileSync(path.join(repo, ".gitignore"), "*.go\n");
  writeFileSync(path.join(repo, "ignored.go"), "package ignored\n");
  git(repo, ["add", "."]);
  git(repo, ["commit", "-m", "tracked architecture"]);
  writeFileSync(path.join(repo, "src", "private.rs"), "fn secret() {}\n");

  const first = inspectTrackedRepository(repo);
  const second = inspectTrackedRepository(repo);

  assert.deepEqual(first.languageCounts, { python: 1, typescript: 1 });
  assert.deepEqual(first.manifestCounts, { node: 1 });
  assert.equal(first.trackedFileCount, 4);
  assert.equal(first.head, git(repo, ["rev-parse", "HEAD"]));
  assert.equal(first.digest, second.digest);
  assert.equal(JSON.stringify(first).includes(repo), false);
  assert.equal(JSON.stringify(first).includes("private.rs"), false);
  assert.equal(JSON.stringify(first).includes("ignored.go"), false);
});

test("repository inspection invokes only bounded read-only Git plumbing", () => {
  const calls = [];
  const outputs = new Map([
    ["ls-files|-z", "src/main.go\0Cargo.toml\0"],
    ["rev-parse|HEAD", `${"a".repeat(40)}\n`],
  ]);
  const facts = inspectTrackedRepository("/fixed/repo", (args) => {
    calls.push(args);
    return outputs.get(args.join("|"));
  });

  assert.deepEqual(calls, [["ls-files", "-z"], ["rev-parse", "HEAD"]]);
  assert.deepEqual(facts.languageCounts, { go: 1 });
  assert.deepEqual(facts.manifestCounts, { rust: 1 });
});

test("candidate evaluation exposes literal requirement, team, repository, and adoption contributions", () => {
  const state = stateWith([{ id: "R1", requirement: "Build the operator workflow" }]);
  const profile = validateDecisionProfile({
    teamLanguages: ["typescript"],
    requirementSignals: { R1: ["browser_ui"] },
  }, state);
  const signals = deriveRequirementSignals(state, profile);
  const repositoryFacts = {
    digest: "facts",
    head: "a".repeat(40),
    languageCounts: { python: 1, typescript: 2 },
    manifestCounts: { node: 1 },
    schemaVersion: "tugboat.repository-language-facts.v1",
    trackedFileCount: 4,
  };

  const candidates = evaluateCandidates({ profile, repositoryFacts, signals });
  const typescript = candidates.find(({ language }) => language === "typescript");
  const go = candidates.find(({ language }) => language === "go");

  assert.equal(candidates[0].language, "typescript");
  assert.equal(typescript.ordinalRankScore, 31);
  assert.deepEqual(typescript.contributions, [
    { capability: 5, points: 15, requirementId: "R1", signal: "browser_ui", source: "profile", type: "requirement", weight: 3 },
    { points: 8, type: "team_affinity" },
    { count: 2, points: 5, type: "repository_affinity" },
    { count: 1, points: 3, type: "manifest_affinity" },
  ]);
  assert.deepEqual(typescript.vetoes, []);
  assert.equal(go.ordinalRankScore, -5);
  assert.deepEqual(go.vetoes, ["required_signal:browser_ui:R1"]);
  assert.deepEqual(go.contributions.at(-1), { points: -5, type: "adoption_penalty" });
});

test("repository affinity makes the viable existing stack win deterministic ties", () => {
  const state = stateWith([{ id: "R1", requirement: "Maintain the existing service" }]);
  const profile = validateDecisionProfile({ requirementSignals: { R1: ["cloud_service"] } }, state);
  const signals = deriveRequirementSignals(state, profile);
  const candidates = evaluateCandidates({
    profile,
    signals,
    repositoryFacts: {
      digest: "facts",
      head: "b".repeat(40),
      languageCounts: { go: 3 },
      manifestCounts: { go: 1 },
      schemaVersion: "tugboat.repository-language-facts.v1",
      trackedFileCount: 4,
    },
  });

  assert.equal(candidates[0].language, "go");
  assert.ok(candidates[0].ordinalRankScore > candidates.find(({ language }) => language === "java").ordinalRankScore);
});

test("compiler fails honestly when hard constraints leave no viable language", () => {
  const state = stateWith([{ id: "R1", requirement: "Ship the client" }]);

  assert.throws(
    () => compileLanguageRecommendation(state, {
      profile: { allowedLanguages: ["go"], requirementSignals: { R1: ["native_ios"] } },
    }),
    /no language survives the declared constraints.*required_signal:native_ios:R1/,
  );
});

test("sparse evidence returns insufficient_evidence without pretending to recommend a winner", () => {
  const state = stateWith([{
    id: "R1",
    requirement: "Build a fast, secure, scalable AI-powered platform.",
    acceptance: "Make it world class.",
  }]);

  const report = compileLanguageRecommendation(state);

  assert.equal(report.recommendation.status, "insufficient_evidence");
  assert.equal(report.recommendation.primary, null);
  assert.deepEqual(report.recommendation.topology, {
    allocations: [],
    kind: "undecided",
    primary: null,
    secondary: null,
  });
  assert.ok(report.rejectedAlternatives.every(({ reason }) => /insufficient grounded evidence/i.test(reason)));
  assert.deepEqual(report.antiSlop.unclassifiedRequirementIds, ["R1"]);
  assert.match(report.uncertainties[0], /R1/);
  assert.equal(JSON.stringify(report).includes('"recommended"'), false);
  assert.match(report.digest, /^[0-9a-f]{64}$/);
});

test("compiler emits auditable why-not output and a canonical digest", () => {
  const state = stateWith([{
    id: "R1",
    requirement: "Deliver the operator workflow.",
    acceptance: "The workflow is usable.",
  }]);
  const facts = {
    digest: "facts-1",
    head: "c".repeat(40),
    languageCounts: { typescript: 1 },
    manifestCounts: { node: 1 },
    schemaVersion: "tugboat.repository-language-facts.v1",
    trackedFileCount: 2,
  };
  const left = compileLanguageRecommendation(state, {
    profile: {
      maxLanguages: 1,
      requirementSignals: { R1: ["browser_ui"] },
      teamLanguages: ["typescript"],
    },
    repositoryFacts: facts,
  });
  const right = compileLanguageRecommendation(state, {
    profile: {
      teamLanguages: ["typescript"],
      requirementSignals: { R1: ["browser_ui"] },
      maxLanguages: 1,
    },
    repositoryFacts: facts,
  });

  assert.equal(left.recommendation.status, "strong");
  assert.deepEqual(left.recommendation.primary, { language: "typescript", label: "TypeScript" });
  assert.equal(left.digest, right.digest);
  assert.equal(left.inputs.profileDigest, right.inputs.profileDigest);
  assert.ok(left.rejectedAlternatives.some(({ language, reason }) => language === "python" && /required_signal:browser_ui:R1/.test(reason)));
  assert.deepEqual(left.antiSlop, {
    classifiedRequirementCount: 1,
    languageCountLimit: 1,
    unclassifiedRequirementIds: [],
    ungroundedSignalCount: 0,
  });
  assert.equal(JSON.stringify(left).includes("performanceScore"), false);
  assert.equal(JSON.stringify(left).includes("universally optimal"), false);
});

test("inferred evidence remains conditional unless explicit constraints or team evidence support it", () => {
  const state = stateWith([{
    id: "R1",
    requirement: "Deliver a browser user interface for internal operators.",
  }]);

  const report = compileLanguageRecommendation(state);

  assert.equal(report.recommendation.status, "conditional");
  assert.deepEqual(report.recommendation.primary, { language: "typescript", label: "TypeScript" });
  assert.match(report.uncertainties.join(" "), /no explicit architecture signals or team-language evidence/i);
});

test("polyglot topology allocates only the requirement cluster that earns a second language", () => {
  const state = stateWith([
    { id: "R1", requirement: "Build the operator surface" },
    { id: "R2", requirement: "Build the native client" },
  ]);
  const report = compileLanguageRecommendation(state, {
    profile: {
      maxLanguages: 2,
      requirementSignals: { R1: ["browser_ui"], R2: ["native_ios"] },
      teamLanguages: ["typescript"],
    },
  });

  assert.equal(report.recommendation.status, "strong");
  assert.deepEqual(report.recommendation.primary, { language: "typescript", label: "TypeScript" });
  assert.deepEqual(report.recommendation.topology, {
    allocations: [
      { language: "typescript", requirementId: "R1" },
      { language: "swift", requirementId: "R2" },
    ],
    kind: "polyglot",
    primary: "typescript",
    secondary: "swift",
  });
  assert.deepEqual(Object.keys(report.recommendation.polyglotTax), [
    "deployment",
    "integration",
    "observability",
    "security",
    "staffing",
  ]);
  assert.deepEqual(report.recommendation.secondaryDecision, {
    bestAlternative: { benefit: 5, language: "swift", requirementIds: ["R2"] },
    failedGates: [],
    gates: {
      benefit_threshold: true,
      constraints_compatible: true,
      max_languages: true,
      operational_tax_exposed: true,
      platform_specific_evidence: true,
    },
    selected: true,
  });
  assert.equal(report.rejectedAlternatives.some(({ language }) => language === "swift"), false);
});

test("maxLanguages one keeps a viable mission single-language and records the failed gate", () => {
  const state = stateWith([{ id: "R1", requirement: "Build a cloud service" }]);
  const report = compileLanguageRecommendation(state, {
    profile: { maxLanguages: 1, requirementSignals: { R1: ["cloud_service"] } },
  });

  assert.equal(report.recommendation.topology.kind, "single_language");
  assert.equal(report.recommendation.topology.secondary, null);
  assert.deepEqual(report.recommendation.secondaryDecision.failedGates, ["max_languages", "platform_specific_evidence"]);
});

test("non-platform specialization cannot trigger polyglot architecture", () => {
  const state = stateWith([
    { id: "R1", requirement: "Train models" },
    { id: "R2", requirement: "Serve requests" },
  ]);
  const report = compileLanguageRecommendation(state, {
    profile: {
      maxLanguages: 2,
      requirementSignals: { R1: ["data_ai"], R2: ["cloud_service"] },
    },
  });

  assert.equal(report.recommendation.topology.kind, "single_language");
  assert.ok(report.recommendation.secondaryDecision.failedGates.includes("platform_specific_evidence"));
});

test("a second language must improve its assigned cluster by two capability levels", () => {
  const state = stateWith([{ id: "R1", requirement: "Build the iOS client" }]);
  const report = compileLanguageRecommendation(state, {
    profile: { maxLanguages: 2, requirementSignals: { R1: ["native_ios"] } },
  });

  assert.equal(report.recommendation.topology.kind, "single_language");
  assert.ok(report.recommendation.secondaryDecision.failedGates.includes("benefit_threshold"));
});

test("allowed-language constraints prevent an otherwise attractive secondary", () => {
  const state = stateWith([
    { id: "R1", requirement: "Build the iOS client" },
    { id: "R2", requirement: "Build the cloud API" },
  ]);
  const profile = validateDecisionProfile({
    allowedLanguages: ["swift"],
    maxLanguages: 2,
    requirementSignals: { R1: ["native_ios"], R2: ["cloud_service"] },
  }, state);
  const signals = deriveRequirementSignals(state, profile);
  const candidates = evaluateCandidates({ profile, signals });
  const topology = selectLanguageTopology({ candidates, catalog: LANGUAGE_CATALOG, profile, signals });

  assert.equal(topology.secondary, null);
  assert.ok(topology.secondaryDecision.failedGates.includes("constraints_compatible"));
});

test("two-language output and allocation are canonical across requirement input order", () => {
  const first = stateWith([
    { id: "R2", requirement: "Native app" },
    { id: "R1", requirement: "Browser app" },
  ]);
  const second = stateWith([
    { id: "R1", requirement: "Browser app" },
    { id: "R2", requirement: "Native app" },
  ]);
  const options = {
    profile: {
      maxLanguages: 2,
      requirementSignals: { R2: ["native_ios"], R1: ["browser_ui"] },
      teamLanguages: ["typescript"],
    },
  };

  const left = compileLanguageRecommendation(first, options);
  const right = compileLanguageRecommendation(second, options);

  assert.deepEqual(left.recommendation.topology.allocations, right.recommendation.topology.allocations);
  assert.equal(left.digest, right.digest);
});
