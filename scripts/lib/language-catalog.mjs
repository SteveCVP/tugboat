export const CATALOG_VERSION = "2026-10-28";

export const SIGNAL_IDS = Object.freeze([
  "browser_ui",
  "cloud_service",
  "concurrent_io",
  "cross_platform_client",
  "data_ai",
  "dotnet_ecosystem",
  "fast_iteration",
  "jvm_ecosystem",
  "low_cold_start",
  "memory_safety",
  "native_android",
  "native_ios",
  "systems_embedded",
]);

export const LANGUAGE_CATALOG = Object.freeze([
  {
    id: "csharp",
    label: "C#",
    sourceUrl: "https://learn.microsoft.com/en-us/dotnet/core/introduction",
    evidence: "Microsoft documents a cross-platform, type-safe and memory-safe runtime with first-class async support.",
    capabilities: {
      cloud_service: 4,
      concurrent_io: 4,
      cross_platform_client: 3,
      dotnet_ecosystem: 5,
      fast_iteration: 3,
      memory_safety: 4,
    },
  },
  {
    id: "go",
    label: "Go",
    sourceUrl: "https://go.dev/solutions/cloud",
    evidence: "Go documents built-in concurrency, fast startup, and efficient, maintainable cloud and network services.",
    capabilities: {
      cloud_service: 5,
      concurrent_io: 5,
      fast_iteration: 3,
      low_cold_start: 5,
      memory_safety: 3,
      systems_embedded: 2,
    },
  },
  {
    id: "java",
    label: "Java",
    sourceUrl: "https://docs.oracle.com/en/java/javase/26/core/virtual-threads.html",
    evidence: "Oracle documents virtual threads for high-throughput applications with many blocking I/O tasks.",
    capabilities: {
      cloud_service: 5,
      concurrent_io: 5,
      fast_iteration: 2,
      jvm_ecosystem: 5,
      memory_safety: 4,
    },
  },
  {
    id: "kotlin",
    label: "Kotlin",
    sourceUrl: "https://kotlinlang.org/docs/multiplatform/kmp-overview.html",
    evidence: "Kotlin documents Android, server, and multiplatform code sharing while retaining native platform access.",
    capabilities: {
      cloud_service: 4,
      cross_platform_client: 5,
      fast_iteration: 3,
      jvm_ecosystem: 5,
      memory_safety: 4,
      native_android: 5,
      native_ios: 3,
    },
  },
  {
    id: "python",
    label: "Python",
    sourceUrl: "https://docs.python.org/3/library/asyncio.html",
    evidence: "Python documents asyncio for I/O-bound structured network code and has a first-class data and ML ecosystem.",
    capabilities: {
      cloud_service: 3,
      concurrent_io: 3,
      data_ai: 5,
      fast_iteration: 5,
      low_cold_start: 3,
      memory_safety: 3,
    },
  },
  {
    id: "rust",
    label: "Rust",
    sourceUrl: "https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html",
    evidence: "Rust documents ownership-based memory safety without a garbage collector for efficient systems software.",
    capabilities: {
      cloud_service: 3,
      concurrent_io: 4,
      low_cold_start: 5,
      memory_safety: 5,
      systems_embedded: 5,
    },
  },
  {
    id: "swift",
    label: "Swift",
    sourceUrl: "https://www.swift.org/about/",
    evidence: "Swift documents compile-time safety, predictable native performance, and mobile, desktop, systems, and cloud use.",
    capabilities: {
      cross_platform_client: 3,
      fast_iteration: 3,
      memory_safety: 5,
      native_ios: 5,
      systems_embedded: 3,
    },
  },
  {
    id: "typescript",
    label: "TypeScript",
    sourceUrl: "https://www.typescriptlang.org/docs/handbook/intro.html",
    evidence: "TypeScript documents static type checking for JavaScript programs while retaining the JavaScript runtime and ecosystem.",
    capabilities: {
      browser_ui: 5,
      cloud_service: 4,
      concurrent_io: 4,
      cross_platform_client: 3,
      fast_iteration: 5,
      low_cold_start: 3,
      memory_safety: 2,
    },
  },
].map((language) => Object.freeze({
  ...language,
  capabilities: Object.freeze({ ...language.capabilities }),
})));

export function validateCatalog(catalog = LANGUAGE_CATALOG) {
  if (!Array.isArray(catalog) || catalog.length === 0) throw new Error("language catalog must be a non-empty array");
  const ids = new Set();
  const knownSignals = new Set(SIGNAL_IDS);
  let previous = "";
  for (const language of catalog) {
    if (!language || typeof language !== "object" || Array.isArray(language)) throw new Error("language catalog entries must be objects");
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(language.id || "")) throw new Error("language id must be a stable lowercase identifier");
    if (ids.has(language.id)) throw new Error(`duplicate language id ${language.id}`);
    if (language.id < previous) throw new Error("language catalog must be sorted by id");
    ids.add(language.id);
    previous = language.id;
    if (typeof language.label !== "string" || !language.label.trim()) throw new Error(`language ${language.id} needs a label`);
    if (!/^https:\/\//.test(language.sourceUrl || "")) throw new Error(`language ${language.id} needs an HTTPS source URL`);
    if (typeof language.evidence !== "string" || language.evidence.length < 20) throw new Error(`language ${language.id} needs concise source evidence`);
    if (!language.capabilities || typeof language.capabilities !== "object" || Array.isArray(language.capabilities)) {
      throw new Error(`language ${language.id} capabilities must be an object`);
    }
    for (const [signal, value] of Object.entries(language.capabilities)) {
      if (!knownSignals.has(signal)) throw new Error(`unknown capability ${signal} on language ${language.id}`);
      if (!Number.isInteger(value) || value < 0 || value > 5) {
        throw new Error(`capability ${signal} on language ${language.id} must be an integer from 0 to 5`);
      }
    }
  }
  return true;
}

validateCatalog();
