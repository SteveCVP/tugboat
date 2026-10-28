import { execFileSync } from "node:child_process";
import path from "node:path";

import { canonicalJson, sha256 } from "./canonical.mjs";
import { CATALOG_VERSION, LANGUAGE_CATALOG, SIGNAL_IDS, validateCatalog } from "./language-catalog.mjs";
import { assertNoSecrets } from "./security.mjs";

const PROFILE_FIELDS = new Set([
  "allowedLanguages",
  "forbiddenLanguages",
  "maxLanguages",
  "priorities",
  "requirementSignals",
  "teamLanguages",
]);
const PRIORITY_IDS = new Set([
  "delivery_speed",
  "ecosystem_fit",
  "operational_simplicity",
  "runtime_efficiency",
  "safety",
]);
const KNOWN_LANGUAGES = new Set(LANGUAGE_CATALOG.map(({ id }) => id));
const KNOWN_SIGNALS = new Set(SIGNAL_IDS);
const MAX_REQUIREMENTS = 500;
const MAX_SIGNALS_PER_REQUIREMENT = 8;
export const MAX_PROFILE_BYTES = 64 * 1024;
const HARD_PLATFORM_SIGNALS = new Set([
  "browser_ui",
  "dotnet_ecosystem",
  "jvm_ecosystem",
  "native_android",
  "native_ios",
  "systems_embedded",
]);
const SIGNAL_PRIORITY = Object.freeze({
  browser_ui: "ecosystem_fit",
  cloud_service: "runtime_efficiency",
  concurrent_io: "runtime_efficiency",
  cross_platform_client: "ecosystem_fit",
  data_ai: "ecosystem_fit",
  dotnet_ecosystem: "ecosystem_fit",
  fast_iteration: "delivery_speed",
  jvm_ecosystem: "ecosystem_fit",
  low_cold_start: "runtime_efficiency",
  memory_safety: "safety",
  native_android: "ecosystem_fit",
  native_ios: "ecosystem_fit",
  systems_embedded: "runtime_efficiency",
});
const MANIFEST_AFFINITY = Object.freeze({
  csharp: "dotnet",
  go: "go",
  java: "jvm",
  kotlin: "jvm",
  python: "python",
  rust: "rust",
  swift: "swift",
  typescript: "node",
});

const INFERENCE_RULES = Object.freeze([
  {
    id: "ledger.browser-ui",
    signal: "browser_ui",
    pattern: /\b(?:responsive )?(?:browser (?:user interface|ui|application)|web application)|\bdesktop and mobile widths\b/i,
  },
  {
    id: "ledger.cloud-service",
    signal: "cloud_service",
    pattern: /\b(?:cloud service|HTTP API|REST API|microservice|serverless function)\b/i,
  },
  {
    id: "ledger.concurrent-io",
    signal: "concurrent_io",
    pattern: /\b(?:high-throughput (?:I\/O|requests|service)|concurrent (?:requests|connections)|blocking I\/O|WebSocket)\b/i,
  },
  {
    id: "ledger.cross-platform-client",
    signal: "cross_platform_client",
    pattern: /\b(?:cross-platform (?:client|mobile|desktop)|shared (?:iOS and Android|mobile) code)\b/i,
  },
  {
    id: "ledger.data-ai",
    signal: "data_ai",
    pattern: /\b(?:machine[- ]learning (?:model )?(?:training|inference)|model training|dataframe analysis|data science pipeline)\b/i,
  },
  {
    id: "ledger.dotnet",
    signal: "dotnet_ecosystem",
    pattern: /\b(?:\.NET ecosystem|ASP\.NET|existing C#)\b/i,
  },
  {
    id: "ledger.fast-iteration",
    signal: "fast_iteration",
    pattern: /\b(?:rapid iteration|same-day prototype|prototype within \d+ days?)\b/i,
  },
  {
    id: "ledger.jvm",
    signal: "jvm_ecosystem",
    pattern: /\b(?:JVM ecosystem|existing Java|Spring Boot)\b/i,
  },
  {
    id: "ledger.low-cold-start",
    signal: "low_cold_start",
    pattern: /\b(?:cold start(?:s)? under \d+ ?ms|sub-second cold start|short-lived CLI binary)\b/i,
  },
  {
    id: "ledger.memory-safety",
    signal: "memory_safety",
    pattern: /\b(?:memory safety without (?:a )?garbage collector|prevent use-after-free|no garbage collector)\b/i,
  },
  {
    id: "ledger.native-android",
    signal: "native_android",
    pattern: /\b(?:native Android|Jetpack Compose|Android SDK)\b/i,
  },
  {
    id: "ledger.native-ios",
    signal: "native_ios",
    pattern: /\b(?:native iOS|SwiftUI|Apple platform app)\b/i,
  },
  {
    id: "ledger.systems-embedded",
    signal: "systems_embedded",
    pattern: /\b(?:embedded device|firmware|operating-system kernel|device driver|systems programming)\b/i,
  },
]);

const EXTENSION_LANGUAGE = new Map([
  [".cjs", "typescript"],
  [".cs", "csharp"],
  [".go", "go"],
  [".java", "java"],
  [".js", "typescript"],
  [".jsx", "typescript"],
  [".kt", "kotlin"],
  [".kts", "kotlin"],
  [".mjs", "typescript"],
  [".py", "python"],
  [".rs", "rust"],
  [".swift", "swift"],
  [".ts", "typescript"],
  [".tsx", "typescript"],
]);

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function requirementsList(state) {
  const requirements = Array.isArray(state?.requirements)
    ? state.requirements
    : isPlainObject(state?.requirements)
      ? Object.values(state.requirements)
      : null;
  if (!requirements || requirements.some((requirement) => !isPlainObject(requirement) || typeof requirement.id !== "string" || !requirement.id)) {
    throw new Error("mission state must include valid requirements");
  }
  return requirements;
}

function sortedUniqueStrings(value, field, { allowEmpty = true, max = 16 } = {}) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${field} must be an array`);
  if (!allowEmpty && value.length === 0) throw new Error(`${field} must not be empty`);
  if (value.length > max) throw new Error(`${field} exceeds ${max} entries`);
  const result = [];
  for (const item of value) {
    if (typeof item !== "string" || !item.trim() || item.length > 64) throw new Error(`${field} entries must be non-empty strings up to 64 characters`);
    result.push(item.trim());
  }
  return [...new Set(result)].sort();
}

function validateLanguages(values, field) {
  for (const language of values) {
    if (!KNOWN_LANGUAGES.has(language)) throw new Error(`${field} contains unknown language ${language}`);
  }
}

export function validateDecisionProfile(profile = {}, state) {
  if (!isPlainObject(profile)) throw new Error("decision profile must be an object");
  if (Buffer.byteLength(JSON.stringify(profile)) > MAX_PROFILE_BYTES) throw new Error("decision profile exceeds 64 KiB");
  assertNoSecrets(profile, "decision profile");
  for (const field of Object.keys(profile)) {
    if (!PROFILE_FIELDS.has(field)) throw new Error(`unknown profile field ${field}`);
  }
  const requirements = requirementsList(state);
  if (requirements.length > MAX_REQUIREMENTS) throw new Error(`mission exceeds ${MAX_REQUIREMENTS} requirements`);

  const teamLanguages = sortedUniqueStrings(profile.teamLanguages, "teamLanguages");
  const allowedLanguages = sortedUniqueStrings(profile.allowedLanguages, "allowedLanguages", { allowEmpty: false });
  const forbiddenLanguages = sortedUniqueStrings(profile.forbiddenLanguages, "forbiddenLanguages");
  validateLanguages(teamLanguages, "teamLanguages");
  validateLanguages(allowedLanguages, "allowedLanguages");
  validateLanguages(forbiddenLanguages, "forbiddenLanguages");
  const overlap = allowedLanguages.filter((language) => forbiddenLanguages.includes(language));
  if (overlap.length) throw new Error(`languages cannot be both allowed and forbidden: ${overlap.join(", ")}`);

  const maxLanguages = profile.maxLanguages ?? 1;
  if (maxLanguages !== 1 && maxLanguages !== 2) throw new Error("maxLanguages must be 1 or 2");

  const priorities = profile.priorities ?? {};
  if (!isPlainObject(priorities)) throw new Error("priorities must be an object");
  const normalizedPriorities = {};
  for (const key of Object.keys(priorities).sort()) {
    if (!PRIORITY_IDS.has(key)) throw new Error(`unknown priority ${key}`);
    if (!Number.isInteger(priorities[key]) || priorities[key] < 1 || priorities[key] > 5) {
      throw new Error(`priority ${key} must be an integer from 1 to 5`);
    }
    normalizedPriorities[key] = priorities[key];
  }

  const requirementIds = new Set(requirements.map(({ id }) => id));
  const mapping = profile.requirementSignals ?? {};
  if (!isPlainObject(mapping)) throw new Error("requirementSignals must be an object");
  const requirementSignals = {};
  for (const requirementId of Object.keys(mapping).sort()) {
    if (!requirementIds.has(requirementId)) throw new Error(`requirementSignals contains unknown requirement ${requirementId}`);
    const signals = sortedUniqueStrings(mapping[requirementId], `requirementSignals.${requirementId}`, {
      allowEmpty: false,
      max: MAX_SIGNALS_PER_REQUIREMENT,
    });
    for (const signal of signals) {
      if (!KNOWN_SIGNALS.has(signal)) throw new Error(`requirementSignals.${requirementId} contains unknown signal ${signal}`);
    }
    requirementSignals[requirementId] = signals;
  }

  return {
    allowedLanguages,
    forbiddenLanguages,
    maxLanguages,
    priorities: normalizedPriorities,
    requirementSignals,
    teamLanguages,
  };
}

export function deriveRequirementSignals(state, normalizedProfile) {
  const requirements = requirementsList(state);
  const profile = normalizedProfile ?? validateDecisionProfile({}, state);
  const byRequirement = {};
  const unclassifiedRequirementIds = [];

  for (const requirement of [...requirements].sort((left, right) => left.id.localeCompare(right.id))) {
    if (requirement.material === false) continue;
    const explicitSignals = profile.requirementSignals[requirement.id] ?? [];
    const signals = explicitSignals.map((signal) => ({
      confidence: "explicit",
      excerpt: `profile.requirementSignals.${requirement.id}`,
      ruleId: "profile.requirementSignals",
      signal,
      source: "profile",
    }));
    const seen = new Set(explicitSignals);
    const ledgerText = [requirement.requirement, requirement.acceptance].filter(Boolean).join("\n").slice(0, 16_000);
    for (const rule of INFERENCE_RULES) {
      if (seen.has(rule.signal)) continue;
      const match = ledgerText.match(rule.pattern);
      if (!match) continue;
      seen.add(rule.signal);
      signals.push({
        confidence: "high",
        excerpt: match[0],
        ruleId: rule.id,
        signal: rule.signal,
        source: "ledger",
      });
    }
    signals.sort((left, right) => left.signal.localeCompare(right.signal));
    byRequirement[requirement.id] = signals;
    if (signals.length === 0) unclassifiedRequirementIds.push(requirement.id);
  }

  return { byRequirement, unclassifiedRequirementIds };
}

function defaultRunGit(repoDir, args) {
  return execFileSync("git", args, {
    cwd: repoDir,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function increment(record, key) {
  record[key] = (record[key] ?? 0) + 1;
}

function manifestKind(relativePath) {
  const base = path.posix.basename(relativePath);
  if (base === "package.json") return "node";
  if (["pyproject.toml", "requirements.txt", "Pipfile"].includes(base)) return "python";
  if (base === "go.mod") return "go";
  if (base === "Cargo.toml") return "rust";
  if (["pom.xml", "build.gradle", "build.gradle.kts"].includes(base)) return "jvm";
  if (base.endsWith(".csproj")) return "dotnet";
  if (base === "Package.swift") return "swift";
  return null;
}

export function inspectTrackedRepository(repoDir, runGit) {
  if (typeof repoDir !== "string" || !repoDir.trim()) throw new Error("repository path is required");
  const invoke = runGit ?? ((args) => defaultRunGit(repoDir, args));
  const rawPaths = String(invoke(["ls-files", "-z"]) ?? "");
  const head = String(invoke(["rev-parse", "HEAD"]) ?? "").trim();
  if (!/^[0-9a-f]{40,64}$/i.test(head)) throw new Error("repository HEAD is not a valid Git object id");
  const trackedPaths = rawPaths.split("\0").filter(Boolean);
  const languageCounts = {};
  const manifestCounts = {};
  for (const relativePath of trackedPaths) {
    if (path.posix.isAbsolute(relativePath) || relativePath.split("/").includes("..")) {
      throw new Error("Git returned an unsafe tracked path");
    }
    const language = EXTENSION_LANGUAGE.get(path.posix.extname(relativePath).toLowerCase());
    if (language) increment(languageCounts, language);
    const manifest = manifestKind(relativePath);
    if (manifest) increment(manifestCounts, manifest);
  }
  const body = {
    schemaVersion: "tugboat.repository-language-facts.v1",
    head: head.toLowerCase(),
    languageCounts: Object.fromEntries(Object.entries(languageCounts).sort(([left], [right]) => left.localeCompare(right))),
    manifestCounts: Object.fromEntries(Object.entries(manifestCounts).sort(([left], [right]) => left.localeCompare(right))),
    trackedFileCount: trackedPaths.length,
  };
  return { ...body, digest: sha256(canonicalJson(body)) };
}

function emptyRepositoryFacts() {
  const body = {
    schemaVersion: "tugboat.repository-language-facts.v1",
    head: null,
    languageCounts: {},
    manifestCounts: {},
    trackedFileCount: 0,
  };
  return { ...body, digest: sha256(canonicalJson(body)) };
}

function normalizeCountRecord(value, field) {
  if (value === undefined) return {};
  if (!isPlainObject(value)) throw new Error(`${field} must be an object`);
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(key)) throw new Error(`${field} contains an invalid key`);
    if (!Number.isInteger(value[key]) || value[key] < 0 || value[key] > 1_000_000) {
      throw new Error(`${field}.${key} must be a non-negative bounded integer`);
    }
    if (value[key] > 0) result[key] = value[key];
  }
  return result;
}

function normalizeRepositoryFacts(value) {
  if (value === undefined) return emptyRepositoryFacts();
  if (!isPlainObject(value)) throw new Error("repository facts must be an object");
  const head = value.head ?? null;
  if (head !== null && !/^[0-9a-f]{40,64}$/i.test(head)) throw new Error("repository facts HEAD is invalid");
  const languageCounts = normalizeCountRecord(value.languageCounts, "languageCounts");
  const manifestCounts = normalizeCountRecord(value.manifestCounts, "manifestCounts");
  const trackedFileCount = value.trackedFileCount ?? 0;
  if (!Number.isInteger(trackedFileCount) || trackedFileCount < 0 || trackedFileCount > 10_000_000) {
    throw new Error("trackedFileCount must be a non-negative bounded integer");
  }
  const body = {
    schemaVersion: "tugboat.repository-language-facts.v1",
    head: head?.toLowerCase() ?? null,
    languageCounts,
    manifestCounts,
    trackedFileCount,
  };
  return { ...body, digest: sha256(canonicalJson(body)) };
}

function priorityAdjustment(profile, signal) {
  const priorityId = SIGNAL_PRIORITY[signal];
  const declared = profile.priorities[priorityId];
  return declared === undefined ? 0 : declared - 3;
}

function repositoryEvidenceCount(repositoryFacts) {
  return [...Object.values(repositoryFacts.languageCounts), ...Object.values(repositoryFacts.manifestCounts)]
    .reduce((sum, count) => sum + count, 0);
}

export function evaluateCandidates({
  catalog = LANGUAGE_CATALOG,
  profile,
  repositoryFacts,
  signals,
}) {
  validateCatalog(catalog);
  if (!profile || !signals?.byRequirement) throw new Error("candidate evaluation requires a normalized profile and requirement signals");
  const facts = normalizeRepositoryFacts(repositoryFacts);
  const hasExistingStack = repositoryEvidenceCount(facts) > 0;
  const allowed = new Set(profile.allowedLanguages);
  const forbidden = new Set(profile.forbiddenLanguages);
  const team = new Set(profile.teamLanguages);
  const operationalPriority = profile.priorities.operational_simplicity ?? 2;
  const ecosystemPriority = profile.priorities.ecosystem_fit ?? 3;

  const candidates = catalog.map((language) => {
    const contributions = [];
    const vetoes = [];
    const unsupportedSignals = [];
    if (allowed.size > 0 && !allowed.has(language.id)) vetoes.push("not_allowed_by_profile");
    if (forbidden.has(language.id)) vetoes.push("forbidden_by_profile");

    for (const requirementId of Object.keys(signals.byRequirement).sort()) {
      for (const signal of signals.byRequirement[requirementId]) {
        const capability = language.capabilities[signal.signal] ?? 0;
        const baseWeight = signal.confidence === "explicit" ? 3 : 2;
        const weight = Math.max(1, baseWeight + priorityAdjustment(profile, signal.signal));
        const points = capability * weight;
        contributions.push({
          capability,
          points,
          requirementId,
          signal: signal.signal,
          source: signal.source,
          type: "requirement",
          weight,
        });
        if (capability === 0) {
          unsupportedSignals.push({ requirementId, signal: signal.signal });
          if (HARD_PLATFORM_SIGNALS.has(signal.signal)) {
            vetoes.push(`required_signal:${signal.signal}:${requirementId}`);
          }
        }
      }
    }

    if (team.has(language.id)) {
      contributions.push({ points: 5 + ecosystemPriority, type: "team_affinity" });
    }
    const repositoryCount = facts.languageCounts[language.id] ?? 0;
    if (repositoryCount > 0) {
      contributions.push({ count: repositoryCount, points: 3 + Math.min(repositoryCount, 5), type: "repository_affinity" });
    }
    const manifestCount = facts.manifestCounts[MANIFEST_AFFINITY[language.id]] ?? 0;
    if (manifestCount > 0) {
      contributions.push({ count: manifestCount, points: 2 + Math.min(manifestCount, 3), type: "manifest_affinity" });
    }
    if (hasExistingStack && repositoryCount === 0 && manifestCount === 0 && !team.has(language.id)) {
      contributions.push({ points: -(3 + operationalPriority), type: "adoption_penalty" });
    }

    const ordinalRankScore = contributions.reduce((sum, contribution) => sum + contribution.points, 0);
    return {
      contributions,
      evidence: language.evidence,
      label: language.label,
      language: language.id,
      ordinalRankScore,
      sourceUrl: language.sourceUrl,
      unsupportedSignals,
      vetoes: [...new Set(vetoes)],
    };
  });

  return candidates.sort((left, right) =>
    left.vetoes.length - right.vetoes.length
    || right.ordinalRankScore - left.ordinalRankScore
    || left.unsupportedSignals.length - right.unsupportedSignals.length
    || left.language.localeCompare(right.language));
}

function missionIdentity(state) {
  return {
    id: state.mission?.id ?? state.metadata?.id ?? "unknown-mission",
    revision: state.revision ?? 0,
    title: state.mission?.title ?? state.metadata?.title ?? "Untitled mission",
  };
}

function rejectedReason(candidate, primary) {
  if (candidate.vetoes.length) return `Vetoed: ${candidate.vetoes.join(", ")}`;
  if (candidate.unsupportedSignals.length) {
    return `Unsupported signals: ${candidate.unsupportedSignals.map(({ requirementId, signal }) => `${signal}:${requirementId}`).join(", ")}`;
  }
  return `Ordinal evidence fit trails ${primary.label} by ${primary.ordinalRankScore - candidate.ordinalRankScore} points`;
}

function hasConstraintVeto(candidate) {
  return candidate.vetoes.some((veto) => veto === "not_allowed_by_profile" || veto === "forbidden_by_profile");
}

function capabilityFor(catalogById, language, signal) {
  return catalogById.get(language)?.capabilities[signal] ?? 0;
}

function clusterBenefit(catalogById, primary, secondary, signals) {
  const requirementIds = [];
  let benefit = 0;
  for (const requirementId of Object.keys(signals.byRequirement).sort()) {
    const requirementSignals = signals.byRequirement[requirementId];
    if (requirementSignals.length === 0) continue;
    const differences = requirementSignals.map(({ signal }) =>
      capabilityFor(catalogById, secondary.language, signal) - capabilityFor(catalogById, primary.language, signal));
    const bestDifference = Math.max(...differences);
    if (differences.every((difference) => difference >= 0) && bestDifference >= 2) {
      requirementIds.push(requirementId);
      benefit = Math.max(benefit, bestDifference);
    }
  }
  return requirementIds.length ? { benefit, language: secondary.language, requirementIds } : null;
}

function coversHardSignals(topology, signals, catalogById) {
  const allocations = new Map(topology.allocations.map(({ language, requirementId }) => [requirementId, language]));
  for (const [requirementId, requirementSignals] of Object.entries(signals.byRequirement)) {
    const language = allocations.get(requirementId);
    for (const { signal } of requirementSignals) {
      if (HARD_PLATFORM_SIGNALS.has(signal) && capabilityFor(catalogById, language, signal) === 0) return false;
    }
  }
  return true;
}

function topologyUnsupportedSignals(topology, signals, catalogById) {
  const allocations = new Map(topology.allocations.map(({ language, requirementId }) => [requirementId, language]));
  const unsupported = [];
  for (const [requirementId, requirementSignals] of Object.entries(signals.byRequirement)) {
    const language = allocations.get(requirementId);
    for (const { signal } of requirementSignals) {
      if (capabilityFor(catalogById, language, signal) === 0) unsupported.push({ requirementId, signal });
    }
  }
  return unsupported;
}

export function selectLanguageTopology({
  candidates,
  catalog = LANGUAGE_CATALOG,
  profile,
  signals,
}) {
  if (!Array.isArray(candidates) || candidates.length === 0) throw new Error("topology selection requires evaluated candidates");
  const catalogById = new Map(catalog.map((language) => [language.id, language]));
  const constraintCompatible = candidates.filter((candidate) => !hasConstraintVeto(candidate));
  if (constraintCompatible.length === 0) throw new Error("no language survives allowed and forbidden language constraints");
  const fullyViable = constraintCompatible.filter(({ vetoes }) => vetoes.length === 0);
  const primary = fullyViable[0] ?? constraintCompatible[0];
  const requirementIds = Object.keys(signals.byRequirement).sort();
  const baseAllocations = requirementIds.map((requirementId) => ({ language: primary.language, requirementId }));
  const platformSpecificEvidence = Object.values(signals.byRequirement).flat().some(({ confidence, signal }) =>
    (confidence === "explicit" || confidence === "high") && HARD_PLATFORM_SIGNALS.has(signal));

  const alternatives = constraintCompatible
    .filter(({ language }) => language !== primary.language)
    .map((candidate) => ({ candidate, cluster: clusterBenefit(catalogById, primary, candidate, signals) }))
    .filter(({ cluster }) => cluster)
    .sort((left, right) =>
      right.cluster.benefit - left.cluster.benefit
      || right.cluster.requirementIds.length - left.cluster.requirementIds.length
      || left.candidate.language.localeCompare(right.candidate.language));
  const allTechnicalAlternatives = candidates
    .filter(({ language }) => language !== primary.language)
    .map((candidate) => ({ candidate, cluster: clusterBenefit(catalogById, primary, candidate, signals) }))
    .filter(({ cluster }) => cluster)
    .sort((left, right) =>
      right.cluster.benefit - left.cluster.benefit
      || right.cluster.requirementIds.length - left.cluster.requirementIds.length
      || left.candidate.language.localeCompare(right.candidate.language));
  const bestTechnical = allTechnicalAlternatives[0] ?? null;
  const bestCompatible = alternatives[0] ?? null;
  const prerequisitesPassed = profile.maxLanguages === 2 && platformSpecificEvidence;
  const gates = {
    benefit_threshold: prerequisitesPassed ? Boolean(bestTechnical) : true,
    constraints_compatible: prerequisitesPassed && bestTechnical ? Boolean(bestCompatible) : true,
    max_languages: profile.maxLanguages === 2,
    operational_tax_exposed: true,
    platform_specific_evidence: platformSpecificEvidence,
  };
  const canSelect = Object.values(gates).every(Boolean) && bestCompatible;
  const polyglotTax = canSelect ? {
    deployment: "Build, release, rollback, and patch two independently versioned toolchains.",
    integration: "Define, version, and compatibility-test every cross-language interface.",
    observability: "Correlate logs, metrics, traces, and failures across both runtimes.",
    security: "Patch and scan two dependency ecosystems, runtimes, and artifact chains.",
    staffing: "Maintain review and on-call competence in both languages.",
  } : null;
  const allocations = canSelect
    ? baseAllocations.map((allocation) => bestCompatible.cluster.requirementIds.includes(allocation.requirementId)
      ? { ...allocation, language: bestCompatible.candidate.language }
      : allocation)
    : baseAllocations;
  const topology = {
    allocations,
    kind: canSelect ? "polyglot" : "single_language",
    primary: primary.language,
    secondary: canSelect ? bestCompatible.candidate.language : null,
  };
  if (canSelect && !coversHardSignals(topology, signals, catalogById)) {
    gates.benefit_threshold = false;
    return {
      allocations: baseAllocations,
      gates,
      kind: "single_language",
      polyglotTax: null,
      primary,
      secondary: null,
      secondaryDecision: {
        bestAlternative: bestTechnical?.cluster ?? null,
        failedGates: ["benefit_threshold"],
        gates,
        selected: false,
      },
    };
  }
  return {
    allocations,
    gates,
    kind: topology.kind,
    polyglotTax,
    primary,
    secondary: canSelect ? bestCompatible.candidate : null,
    secondaryDecision: {
      bestAlternative: bestTechnical?.cluster ?? null,
      failedGates: Object.entries(gates).filter(([, passed]) => !passed).map(([gate]) => gate),
      gates,
      selected: Boolean(canSelect),
    },
  };
}

export function compileLanguageRecommendation(state, options = {}) {
  requirementsList(state);
  const profile = validateDecisionProfile(options.profile ?? {}, state);
  const signals = deriveRequirementSignals(state, profile);
  const repositoryFacts = normalizeRepositoryFacts(
    options.repositoryFacts ?? (options.repoDir ? inspectTrackedRepository(options.repoDir, options.runGit) : undefined),
  );
  const candidates = evaluateCandidates({ profile, repositoryFacts, signals });
  const topology = selectLanguageTopology({ candidates, profile, signals });
  const catalogById = new Map(LANGUAGE_CATALOG.map((language) => [language.id, language]));
  if (!coversHardSignals(topology, signals, catalogById)) {
    const reasons = topology.primary.vetoes.filter((veto) => veto.startsWith("required_signal:"));
    throw new Error(`no language survives the declared constraints (${[...new Set(reasons)].join(", ")})`);
  }

  const requirementIds = Object.keys(signals.byRequirement);
  const classifiedRequirementCount = requirementIds.length - signals.unclassifiedRequirementIds.length;
  const explicitSignalCount = Object.values(signals.byRequirement).flat().filter(({ source }) => source === "profile").length;
  const hasChoiceEvidence = profile.teamLanguages.length > 0
    || profile.allowedLanguages.length > 0
    || repositoryEvidenceCount(repositoryFacts) > 0;
  const insufficient = classifiedRequirementCount === 0 && !hasChoiceEvidence;
  const primary = topology.primary;
  const topologyUnsupported = topologyUnsupportedSignals(topology, signals, catalogById);
  const completeCoverage = classifiedRequirementCount === requirementIds.length && requirementIds.length > 0;
  const strong = !insufficient
    && completeCoverage
    && topologyUnsupported.length === 0
    && (explicitSignalCount > 0 || profile.teamLanguages.length > 0 || profile.allowedLanguages.length > 0);
  const status = insufficient ? "insufficient_evidence" : strong ? "strong" : "conditional";
  const uncertainties = [];
  if (signals.unclassifiedRequirementIds.length) {
    uncertainties.push(`No architecture signal is grounded for requirements: ${signals.unclassifiedRequirementIds.join(", ")}`);
  }
  if (explicitSignalCount === 0 && profile.teamLanguages.length === 0) {
    uncertainties.push("There are no explicit architecture signals or team-language evidence; inferred and repository evidence remain conditional.");
  }
  if (topologyUnsupported.length) {
    uncertainties.push(`The selected topology does not cover: ${topologyUnsupported.map(({ requirementId, signal }) => `${signal}:${requirementId}`).join(", ")}`);
  }
  if (insufficient) {
    uncertainties.push("Declare requirementSignals, teamLanguages, allowedLanguages, or retain an existing tracked stack before selecting an implementation language.");
  }

  const profileDigest = sha256(canonicalJson(profile));
  const signalsDigest = sha256(canonicalJson(signals));
  const catalogDigest = sha256(canonicalJson(LANGUAGE_CATALOG));
  const recommendationTopology = insufficient ? {
    allocations: [],
    kind: "undecided",
    primary: null,
    secondary: null,
  } : {
    allocations: topology.allocations,
    kind: topology.kind,
    primary: primary.language,
    secondary: topology.secondary?.language ?? null,
  };
  const body = {
    schemaVersion: "tugboat.language-recommendation.v1",
    mission: missionIdentity(state),
    catalog: { digest: catalogDigest, version: CATALOG_VERSION },
    inputs: {
      profileDigest,
      repositoryFactsDigest: repositoryFacts.digest,
      signalsDigest,
    },
    profile,
    requirementSignals: signals.byRequirement,
    repositoryFacts,
    candidates,
    recommendation: {
      primary: insufficient ? null : { language: primary.language, label: primary.label },
      polyglotTax: topology.polyglotTax,
      rationale: insufficient
        ? ["The available evidence cannot justify selecting or rejecting an implementation language."]
        : [
            `${primary.label} has the highest surviving evidence-grounded ordinal fit.`,
            topology.secondary
              ? `${topology.secondary.label} is limited to requirements ${topology.allocations.filter(({ language }) => language === topology.secondary.language).map(({ requirementId }) => requirementId).join(", ")}.`
              : "No second language cleared every complexity gate.",
            "The rank reflects declared requirements and adoption context, not a performance benchmark.",
          ],
      secondaryDecision: topology.secondaryDecision,
      status,
      topology: recommendationTopology,
    },
    rejectedAlternatives: candidates
      .filter(({ language }) => insufficient || (language !== primary.language && language !== topology.secondary?.language))
      .map((candidate) => ({
        language: candidate.language,
        ordinalRankScore: candidate.ordinalRankScore,
        reason: insufficient
          ? "Insufficient grounded evidence to select or reject this language."
          : rejectedReason(candidate, primary),
      })),
    uncertainties,
    antiSlop: {
      classifiedRequirementCount,
      languageCountLimit: profile.maxLanguages,
      unclassifiedRequirementIds: signals.unclassifiedRequirementIds,
      ungroundedSignalCount: 0,
    },
  };
  assertNoSecrets(body, "language recommendation");
  return { ...body, digest: sha256(canonicalJson(body)) };
}
