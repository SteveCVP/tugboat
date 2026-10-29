import { createHash } from "node:crypto";

const SUPPORTED = new Set(["typescript", "python", "go", "openapi", "graphql", "sql", "terraform", "cloudformation-cdk", "github-actions", "oci"]);
const HTTP_METHODS = new Set(["get", "put", "post", "delete", "options", "head", "patch", "trace"]);

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function point(source, offset) {
  let line = 1;
  let column = 1;
  for (let index = 0; index < offset; index += 1) {
    if (source[index] === "\n") {
      line += 1;
      column = 1;
    } else column += 1;
  }
  return { line, column, offset };
}

function sourceSpan(sourceName, source, start, end) {
  return { source: sourceName, start: point(source, start), end: point(source, end) };
}

function scan(source, { hashComment = false, sqlComment = false } = {}) {
  const tokens = [];
  const stack = [];
  const pairs = { "(": ")", "[": "]", "{": "}" };
  let index = 0;
  while (index < source.length) {
    const start = index;
    const character = source[index];
    if (/\s/u.test(character)) { index += 1; continue; }
    if (hashComment && character === "#") {
      while (index < source.length && source[index] !== "\n") index += 1;
      continue;
    }
    if (source.startsWith("//", index) || (sqlComment && source.startsWith("--", index))) {
      while (index < source.length && source[index] !== "\n") index += 1;
      continue;
    }
    if (source.startsWith("/*", index)) {
      const end = source.indexOf("*/", index + 2);
      if (end < 0) throw new Error(`Unterminated comment at ${index}`);
      index = end + 2;
      continue;
    }
    if (/[A-Za-z_$]/u.test(character)) {
      index += 1;
      while (index < source.length && /[A-Za-z0-9_$]/u.test(source[index])) index += 1;
      tokens.push({ kind: "word", value: source.slice(start, index), start, end: index });
      continue;
    }
    if (/[0-9]/u.test(character)) {
      index += 1;
      while (index < source.length && /[A-Za-z0-9_.]/u.test(source[index])) index += 1;
      tokens.push({ kind: "number", value: source.slice(start, index), start, end: index });
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      const quote = character;
      index += 1;
      let closed = false;
      while (index < source.length) {
        if (source[index] === "\\") { index += 2; continue; }
        if (source[index] === quote) { index += 1; closed = true; break; }
        index += 1;
      }
      if (!closed) throw new Error(`Unterminated string at ${start}`);
      tokens.push({ kind: "string", value: source.slice(start, index), start, end: index });
      continue;
    }
    if (pairs[character]) stack.push({ value: character, offset: start });
    else if (Object.values(pairs).includes(character)) {
      const opening = stack.pop();
      if (!opening || pairs[opening.value] !== character) throw new Error(`Unbalanced ${character} at ${start}`);
    }
    tokens.push({ kind: "punct", value: character, start, end: start + 1 });
    index += 1;
  }
  if (stack.length) throw new Error(`Unclosed ${stack.at(-1).value} at ${stack.at(-1).offset}`);
  return tokens;
}

function tokenSignature(tokens) {
  return tokens.map((token) => token.value).join(" ");
}

function entry(subject, signature, token, sourceName, source, kind, metadata = {}) {
  return { subject, signature, kind, span: sourceSpan(sourceName, source, token.start, token.end), metadata };
}

function matchingBraceIndex(tokens, openIndex) {
  if (tokens[openIndex]?.value !== "{") throw new Error("Expected opening brace");
  let depth = 0;
  for (let index = openIndex; index < tokens.length; index += 1) {
    if (tokens[index].value === "{") depth += 1;
    if (tokens[index].value === "}") depth -= 1;
    if (depth === 0) return index;
  }
  throw new Error(`Unclosed declaration at ${tokens[openIndex].start}`);
}

function parseTypeScript(source, sourceName) {
  const tokens = scan(source);
  const symbols = new Map();
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.value === "{") depth += 1;
    else if (token.value === "}") depth -= 1;
    if (depth !== 0 || token.value !== "export") continue;
    if (tokens[index + 1]?.value === "*") return { unsupported: { subject: "export *", token } };
    let cursor = index + 1;
    if (tokens[cursor]?.value === "default") cursor += 1;
    const kind = tokens[cursor]?.value;
    if (!["function", "class", "interface", "type", "enum", "const", "let", "var"].includes(kind)) {
      return { unsupported: { subject: tokenSignature(tokens.slice(index, Math.min(tokens.length, index + 4))), token } };
    }
    const nameToken = tokens[cursor + 1];
    if (!nameToken || nameToken.kind !== "word") throw new Error(`Missing exported name at ${token.start}`);
    let end = cursor + 2;
    let localDepth = 0;
    while (end < tokens.length) {
      const value = tokens[end].value;
      if (value === "(" || value === "[") localDepth += 1;
      if (value === ")" || value === "]") localDepth -= 1;
      if (localDepth === 0 && (value === ";" || value === "{")) break;
      end += 1;
    }
    if (["class", "interface", "enum"].includes(kind) && tokens[end]?.value === "{") end = matchingBraceIndex(tokens, end) + 1;
    else if (["type", "const", "let", "var"].includes(kind)) {
      while (end < tokens.length && tokens[end].value !== ";") {
        if (tokens[end].value === "{") end = matchingBraceIndex(tokens, end);
        end += 1;
      }
    }
    const subject = `${kind}:${nameToken.value}`;
    symbols.set(subject, entry(subject, tokenSignature(tokens.slice(cursor, end)), nameToken, sourceName, source, kind));
  }
  return { symbols };
}

function parsePython(source, sourceName) {
  const tokens = scan(source, { hashComment: true });
  for (let index = 0; index < tokens.length - 2; index += 1) {
    if (tokens[index].value === "from" && tokens.slice(index + 1, index + 8).some((token) => token.value === "import") && tokens.slice(index + 1, index + 10).some((token) => token.value === "*")) {
      return { unsupported: { subject: "star import", token: tokens[index] } };
    }
  }
  const symbols = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    const location = point(source, token.start);
    if (location.column !== 1 || !["def", "class"].includes(token.value)) continue;
    const nameToken = tokens[index + 1];
    if (!nameToken || nameToken.kind !== "word") throw new Error(`Missing ${token.value} name at ${token.start}`);
    if (nameToken.value.startsWith("_")) continue;
    let end = index + 2;
    while (end < tokens.length && tokens[end].value !== ":") end += 1;
    if (end >= tokens.length) throw new Error(`Missing declaration colon at ${token.start}`);
    let signatureEnd = end;
    if (token.value === "class") {
      while (signatureEnd < tokens.length) {
        const next = tokens[signatureEnd];
        const nextLocation = point(source, next.start);
        if (nextLocation.column === 1 && ["def", "class"].includes(next.value)) break;
        signatureEnd += 1;
      }
    }
    const subject = `${token.value}:${nameToken.value}`;
    symbols.set(subject, entry(subject, tokenSignature(tokens.slice(index, signatureEnd)), nameToken, sourceName, source, token.value));
  }
  return { symbols };
}

function parseGo(source, sourceName) {
  const tokens = scan(source);
  for (let index = 0; index < tokens.length - 1; index += 1) {
    if (tokens[index].value === "import" && tokens[index + 1].value === "\"C\"") return { unsupported: { subject: "cgo import", token: tokens[index] } };
  }
  const symbols = new Map();
  let depth = 0;
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.value === "{") depth += 1;
    else if (token.value === "}") depth -= 1;
    if (depth !== 0 || !["func", "type", "var", "const"].includes(token.value)) continue;
    let nameIndex = index + 1;
    if (token.value === "func" && tokens[nameIndex]?.value === "(") return { unsupported: { subject: "exported method set", token } };
    const nameToken = tokens[nameIndex];
    if (!nameToken || nameToken.kind !== "word") throw new Error(`Missing ${token.value} name at ${token.start}`);
    if (!/^[A-Z]/u.test(nameToken.value)) continue;
    let end = nameIndex + 1;
    let localDepth = 0;
    while (end < tokens.length) {
      const value = tokens[end].value;
      if (value === "(" || value === "[") localDepth += 1;
      if (value === ")" || value === "]") localDepth -= 1;
      if (localDepth === 0 && (value === "{" || value === ";")) break;
      end += 1;
    }
    if (token.value === "type" && tokens[end]?.value === "{") end = matchingBraceIndex(tokens, end) + 1;
    const subject = `${token.value}:${nameToken.value}`;
    symbols.set(subject, entry(subject, tokenSignature(tokens.slice(index, end)), nameToken, sourceName, source, token.value));
  }
  return { symbols };
}

function parseGraphql(source, sourceName) {
  const tokens = scan(source, { hashComment: true });
  const unsupported = tokens.find((token) => token.value === "directive" || token.value === "extend");
  if (unsupported) return { unsupported: { subject: unsupported.value, token: unsupported } };
  const symbols = new Map();
  for (let index = 0; index < tokens.length; index += 1) {
    const declaration = tokens[index];
    if (!["type", "input", "interface", "enum", "scalar", "union"].includes(declaration.value)) continue;
    const nameToken = tokens[index + 1];
    if (!nameToken || nameToken.kind !== "word") throw new Error(`Missing GraphQL type name at ${declaration.start}`);
    const typeSubject = `${declaration.value}:${nameToken.value}`;
    symbols.set(typeSubject, entry(typeSubject, declaration.value, nameToken, sourceName, source, declaration.value));
    let open = index + 2;
    while (open < tokens.length && tokens[open].value !== "{" && tokens[open].value !== "=") open += 1;
    if (open >= tokens.length || tokens[open].value !== "{") continue;
    let cursor = open + 1;
    while (cursor < tokens.length && tokens[cursor].value !== "}") {
      const fieldToken = tokens[cursor];
      if (fieldToken.kind !== "word") { cursor += 1; continue; }
      cursor += 1;
      let argumentDepth = 0;
      if (tokens[cursor]?.value === "(") {
        do {
          if (tokens[cursor].value === "(") argumentDepth += 1;
          if (tokens[cursor].value === ")") argumentDepth -= 1;
          cursor += 1;
        } while (cursor < tokens.length && argumentDepth > 0);
      }
      if (tokens[cursor]?.value !== ":") throw new Error(`Missing GraphQL field type at ${fieldToken.start}`);
      cursor += 1;
      const typeTokens = [];
      while (cursor < tokens.length && !["}", "@"].includes(tokens[cursor].value)) {
        if (tokens[cursor].kind === "word" && typeTokens.length > 0 && !["[", "!"].includes(typeTokens.at(-1)?.value)) break;
        typeTokens.push(tokens[cursor]);
        cursor += 1;
      }
      const subject = `field:${nameToken.value}.${fieldToken.value}`;
      symbols.set(subject, entry(subject, tokenSignature(typeTokens), fieldToken, sourceName, source, "field", { parentKind: declaration.value }));
      while (cursor < tokens.length && tokens[cursor].value === "@") {
        cursor += 1;
        while (cursor < tokens.length && tokens[cursor].value !== "}" && tokens[cursor].kind !== "word") cursor += 1;
      }
    }
  }
  return { symbols };
}

function parseSql(source, sourceName) {
  const tokens = scan(source, { sqlComment: true });
  const first = tokens[0]?.value?.toUpperCase();
  if (["DO", "EXEC", "EXECUTE", "CALL"].includes(first) || tokens.some((token) => token.value === "$$")) {
    return { unsupported: { subject: tokens[0]?.value ?? "procedural SQL", token: tokens[0] ?? { start: 0, end: 0 } } };
  }
  const symbols = new Map();
  let index = 0;
  while (index < tokens.length) {
    if (tokens[index].value.toUpperCase() !== "CREATE" || tokens[index + 1]?.value.toUpperCase() !== "TABLE") {
      return { unsupported: { subject: tokens[index].value, token: tokens[index] } };
    }
    index += 2;
    if (tokens[index]?.value.toUpperCase() === "IF") {
      if (tokens[index + 1]?.value.toUpperCase() !== "NOT" || tokens[index + 2]?.value.toUpperCase() !== "EXISTS") throw new Error(`Malformed IF NOT EXISTS at ${tokens[index].start}`);
      index += 3;
    }
    const tableToken = tokens[index];
    if (!tableToken || tableToken.kind !== "word") throw new Error(`Missing table name at ${tokens[index - 1].end}`);
    const table = tableToken.value;
    const tableSubject = `table:${table}`;
    symbols.set(tableSubject, entry(tableSubject, "table", tableToken, sourceName, source, "table"));
    index += 1;
    if (tokens[index]?.value !== "(") throw new Error(`Missing table columns at ${tableToken.end}`);
    index += 1;
    while (index < tokens.length && tokens[index].value !== ")") {
      const columnToken = tokens[index];
      if (!columnToken || columnToken.kind !== "word") throw new Error(`Missing column name at ${tokens[index - 1]?.end ?? 0}`);
      index += 1;
      const definition = [];
      let nested = 0;
      while (index < tokens.length) {
        const value = tokens[index].value;
        if (value === "(") nested += 1;
        if (value === ")" && nested > 0) nested -= 1;
        if (nested === 0 && (value === "," || value === ")")) break;
        definition.push(tokens[index]);
        index += 1;
      }
      if (definition.length === 0) throw new Error(`Missing type for column ${columnToken.value}`);
      const subject = `column:${table}.${columnToken.value}`;
      symbols.set(subject, entry(subject, tokenSignature(definition).toUpperCase(), columnToken, sourceName, source, "column"));
      if (tokens[index]?.value === ",") index += 1;
    }
    if (tokens[index]?.value !== ")") throw new Error(`Unclosed table ${table}`);
    index += 1;
    if (tokens[index]?.value === ";") index += 1;
  }
  return { symbols };
}

function jsonAst(source) {
  let index = 0;
  function whitespace() { while (index < source.length && /\s/u.test(source[index])) index += 1; }
  function stringNode() {
    const start = index;
    if (source[index] !== "\"") throw new Error(`Expected string at ${index}`);
    index += 1;
    while (index < source.length) {
      if (source[index] === "\\") { index += 2; continue; }
      if (source[index] === "\"") { index += 1; return { value: JSON.parse(source.slice(start, index)), start, end: index }; }
      index += 1;
    }
    throw new Error(`Unterminated JSON string at ${start}`);
  }
  function valueNode() {
    whitespace();
    const start = index;
    if (source[index] === "{") {
      index += 1;
      const properties = new Map();
      const value = {};
      whitespace();
      while (source[index] !== "}") {
        const key = stringNode();
        whitespace();
        if (source[index] !== ":") throw new Error(`Expected colon at ${index}`);
        index += 1;
        const child = valueNode();
        value[key.value] = child.value;
        properties.set(key.value, { key, node: child });
        whitespace();
        if (source[index] === ",") { index += 1; whitespace(); continue; }
        if (source[index] !== "}") throw new Error(`Expected object close at ${index}`);
      }
      index += 1;
      return { value, start, end: index, properties };
    }
    if (source[index] === "[") {
      index += 1;
      const items = [];
      whitespace();
      while (source[index] !== "]") {
        items.push(valueNode());
        whitespace();
        if (source[index] === ",") { index += 1; whitespace(); continue; }
        if (source[index] !== "]") throw new Error(`Expected array close at ${index}`);
      }
      index += 1;
      return { value: items.map((item) => item.value), start, end: index, items };
    }
    if (source[index] === "\"") return stringNode();
    const match = source.slice(index).match(/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u);
    if (!match) throw new Error(`Invalid JSON value at ${index}`);
    index += match[0].length;
    return { value: JSON.parse(match[0]), start, end: index };
  }
  const node = valueNode();
  whitespace();
  if (index !== source.length) throw new Error(`Unexpected JSON at ${index}`);
  return node;
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  return value;
}

function parseOpenApi(source, sourceName) {
  if (!source.trimStart().startsWith("{")) return { unsupported: { subject: "non-JSON OpenAPI", token: { start: 0, end: Math.min(1, source.length) } } };
  const root = jsonAst(source);
  if (!root.value || typeof root.value !== "object" || !String(root.value.openapi ?? "").startsWith("3.")) throw new Error("OpenAPI 3.x document required");
  const paths = root.properties?.get("paths")?.node;
  if (!paths || !paths.properties) throw new Error("OpenAPI paths object required");
  const symbols = new Map();
  for (const [route, routeEntry] of paths.properties.entries()) {
    if (!routeEntry.node.properties) throw new Error(`OpenAPI path ${route} must be an object`);
    for (const [method, operationEntry] of routeEntry.node.properties.entries()) {
      if (!HTTP_METHODS.has(method.toLowerCase())) continue;
      const subject = `operation:${method.toUpperCase()} ${route}`;
      const signature = JSON.stringify(stable(operationEntry.node.value));
      const token = operationEntry.key;
      symbols.set(subject, entry(subject, signature, token, sourceName, source, "operation"));
    }
  }
  const schemas = root.properties?.get("components")?.node?.properties?.get("schemas")?.node;
  if (schemas?.properties) {
    for (const [name, schemaEntry] of schemas.properties.entries()) {
      const subject = `schema:${name}`;
      symbols.set(subject, entry(subject, JSON.stringify(stable(schemaEntry.node.value)), schemaEntry.key, sourceName, source, "schema"));
    }
  }
  return { symbols };
}

function parseTerraform(source, sourceName) {
  const tokens = scan(source, { hashComment: true });
  const symbols = new Map();
  let index = 0;
  while (index < tokens.length) {
    const declaration = tokens[index];
    if (declaration.value !== "resource") return { unsupported: { subject: declaration.value, token: declaration } };
    const typeToken = tokens[index + 1];
    const nameToken = tokens[index + 2];
    if (typeToken?.kind !== "string" || nameToken?.kind !== "string" || tokens[index + 3]?.value !== "{") throw new Error(`Malformed Terraform resource at ${declaration.start}`);
    const type = JSON.parse(typeToken.value);
    const name = JSON.parse(nameToken.value);
    const close = matchingBraceIndex(tokens, index + 3);
    const block = tokens.slice(index, close + 1);
    const broadNetwork = block.some((token) => token.kind === "string" && JSON.parse(token.value) === "0.0.0.0/0");
    const iam = type.includes("_iam_") || type.startsWith("aws_iam");
    const network = type.includes("security_group") || type.includes("network_acl") || type.includes("route");
    const kind = iam ? "iam_resource" : network ? "network_resource" : "resource";
    const subject = `resource:${name}`;
    symbols.set(subject, entry(subject, tokenSignature(block), nameToken, sourceName, source, kind, { resourceType: type, iam, broadNetwork }));
    index = close + 1;
  }
  return { symbols };
}

function parseCloudFormation(source, sourceName) {
  if (!source.trimStart().startsWith("{")) return { unsupported: { subject: "non-JSON CloudFormation", token: { start: 0, end: Math.min(1, source.length) } } };
  const root = jsonAst(source);
  const resources = root.properties?.get("Resources")?.node;
  if (!resources?.properties) throw new Error("CloudFormation Resources object required");
  const symbols = new Map();
  for (const [logicalId, resourceEntry] of resources.properties.entries()) {
    const type = resourceEntry.node.value?.Type;
    if (typeof type !== "string") throw new Error(`CloudFormation resource ${logicalId} needs Type`);
    const iam = type.startsWith("AWS::IAM::");
    const network = ["AWS::EC2::SecurityGroup", "AWS::EC2::NetworkAcl", "AWS::EC2::Route"].includes(type);
    const encoded = JSON.stringify(stable(resourceEntry.node.value));
    const broadNetwork = encoded.includes("0.0.0.0/0");
    const kind = iam ? "iam_resource" : network ? "network_resource" : "resource";
    const subject = `resource:${logicalId}`;
    symbols.set(subject, entry(subject, encoded, resourceEntry.key, sourceName, source, kind, { resourceType: type, iam, broadNetwork }));
  }
  const sourceDigestEntry = root.properties?.get("Metadata")?.node?.properties?.get("TugboatSourceDigest");
  return {
    symbols,
    metadata: sourceDigestEntry ? { sourceDigest: sourceDigestEntry.node.value, sourceDigestToken: sourceDigestEntry.key } : {},
  };
}

function parseGithubActions(source, sourceName) {
  if (!source.trimStart().startsWith("{")) return { unsupported: { subject: "non-JSON workflow", token: { start: 0, end: Math.min(1, source.length) } } };
  const root = jsonAst(source);
  const symbols = new Map();
  const triggers = root.properties?.get("on")?.node;
  if (!triggers) throw new Error("GitHub Actions workflow needs on");
  if (triggers.properties) {
    for (const [name, trigger] of triggers.properties.entries()) {
      const subject = `trigger:${name}`;
      symbols.set(subject, entry(subject, JSON.stringify(stable(trigger.node.value)), trigger.key, sourceName, source, "trigger", { dangerous: ["pull_request_target", "workflow_run"].includes(name) }));
    }
  } else if (typeof triggers.value === "string") {
    const subject = `trigger:${triggers.value}`;
    symbols.set(subject, entry(subject, triggers.value, triggers, sourceName, source, "trigger", { dangerous: ["pull_request_target", "workflow_run"].includes(triggers.value) }));
  } else throw new Error("GitHub Actions on must be an object or string");
  const permissions = root.properties?.get("permissions")?.node;
  if (permissions?.properties) {
    for (const [scope, permission] of permissions.properties.entries()) {
      const subject = `permission:${scope}`;
      symbols.set(subject, entry(subject, String(permission.node.value), permission.key, sourceName, source, "permission", { write: permission.node.value === "write" }));
    }
  }
  const jobs = root.properties?.get("jobs")?.node;
  if (!jobs?.properties) throw new Error("GitHub Actions jobs object required");
  function visitSecrets(node, pathParts) {
    if (typeof node?.value === "string" && node.value.includes("${{ secrets.")) {
      const subject = `secret:${pathParts.join(".")}`;
      symbols.set(subject, entry(subject, "secret-reference", node, sourceName, source, "secret_reference", { secret: true }));
      return;
    }
    if (node?.properties) for (const [key, child] of node.properties.entries()) visitSecrets(child.node, [...pathParts, key]);
    if (node?.items) node.items.forEach((child, index) => visitSecrets(child, [...pathParts, String(index)]));
  }
  for (const [jobName, jobEntry] of jobs.properties.entries()) {
    const steps = jobEntry.node.properties?.get("steps")?.node;
    if (steps?.items) {
      steps.items.forEach((step, stepIndex) => {
        const uses = step.properties?.get("uses");
        if (!uses || typeof uses.node.value !== "string") return;
        const reference = uses.node.value;
        const revision = reference.includes("@") ? reference.slice(reference.lastIndexOf("@") + 1) : "";
        const pinned = /^[0-9a-f]{40}$/u.test(revision) || /^sha256:[0-9a-f]{64}$/u.test(revision);
        const subject = `action:${jobName}.${stepIndex}`;
        symbols.set(subject, entry(subject, reference, uses.node, sourceName, source, "action_reference", { pinned }));
      });
    }
    visitSecrets(jobEntry.node, ["jobs", jobName]);
  }
  return { symbols };
}

function parseOci(source, sourceName) {
  if (!source.trimStart().startsWith("{")) return { unsupported: { subject: "non-JSON OCI inspection", token: { start: 0, end: Math.min(1, source.length) } } };
  const root = jsonAst(source);
  if (root.value?.schemaVersion !== 2) return { unsupported: { subject: `OCI schemaVersion ${String(root.value?.schemaVersion ?? "missing")}`, token: root.properties?.get("schemaVersion")?.node ?? { start: 0, end: 1 } } };
  const config = root.properties?.get("configData")?.node;
  const layers = root.properties?.get("layers")?.node;
  if (!config?.properties || !layers?.items) throw new Error("OCI inspection requires configData and layers");
  const symbols = new Map();
  const user = config.properties.get("User")?.node;
  const entrypointNode = config.properties.get("Entrypoint")?.node;
  const cmd = config.properties.get("Cmd")?.node;
  const capabilities = config.properties.get("CapAdd")?.node;
  if (!user || !entrypointNode || !cmd || !capabilities?.items) throw new Error("OCI configData is incomplete");
  symbols.set("config:user", entry("config:user", String(user.value), user, sourceName, source, "user", { root: ["", "0", "root"].includes(String(user.value).split(":")[0]) }));
  symbols.set("config:entrypoint", entry("config:entrypoint", JSON.stringify(entrypointNode.value), entrypointNode, sourceName, source, "entrypoint"));
  symbols.set("config:cmd", entry("config:cmd", JSON.stringify(cmd.value), cmd, sourceName, source, "command"));
  capabilities.items.forEach((capability) => {
    const subject = `capability:${capability.value}`;
    symbols.set(subject, entry(subject, String(capability.value), capability, sourceName, source, "capability", { capability: true }));
  });
  layers.items.forEach((layer, index) => {
    const digestNode = layer.properties?.get("digest")?.node;
    if (!digestNode || typeof digestNode.value !== "string") throw new Error(`OCI layer ${index} needs digest`);
    const subject = `layer:${index}`;
    symbols.set(subject, entry(subject, digestNode.value, digestNode, sourceName, source, "layer"));
  });
  const provenance = root.properties?.get("provenance")?.node?.properties?.get("subjectDigest")?.node;
  if (provenance) symbols.set("provenance:subject", entry("provenance:subject", String(provenance.value), provenance, sourceName, source, "provenance"));
  return { symbols };
}

function parserFor(analyzer) {
  return {
    typescript: parseTypeScript,
    python: parsePython,
    go: parseGo,
    openapi: parseOpenApi,
    graphql: parseGraphql,
    sql: parseSql,
    terraform: parseTerraform,
    "cloudformation-cdk": parseCloudFormation,
    "github-actions": parseGithubActions,
    oci: parseOci,
  }[analyzer];
}

function insufficient(analyzer, code, subject, message, span) {
  return {
    status: "insufficient_evidence",
    compatibility: { verdict: "insufficient_evidence", summary: `The ${analyzer} analyzer could not prove compatibility.` },
    effects: [],
    uncertainty: [{ code, subject, message, span }],
    counterexamples: [],
  };
}

function compare(analyzer, before, after) {
  const changes = [];
  const subjects = [...new Set([...before.keys(), ...after.keys()])].sort();
  for (const subject of subjects) {
    const prior = before.get(subject);
    const next = after.get(subject);
    if (!prior) {
      const unsafeGraphqlInput = analyzer === "graphql" && next.kind === "field" && next.metadata.parentKind === "input" && next.signature.includes("!");
      const unsafeSqlColumn = analyzer === "sql" && next.kind === "column" && next.signature.includes("NOT NULL") && !next.signature.includes("DEFAULT");
      const unsafeInfrastructure = ["terraform", "cloudformation-cdk"].includes(analyzer) && (next.metadata.iam || next.metadata.broadNetwork);
      const unsafeWorkflow = analyzer === "github-actions" && (next.metadata.dangerous || next.metadata.write || next.metadata.pinned === false || next.metadata.secret);
      const unsafeImage = analyzer === "oci" && (next.metadata.root || next.metadata.capability);
      changes.push({ subject, change: "add", compatibility: unsafeGraphqlInput || unsafeSqlColumn || unsafeInfrastructure || unsafeWorkflow || unsafeImage ? "breaking" : "compatible", current: next });
    }
    else if (!next) changes.push({ subject, change: "remove", compatibility: "breaking", current: prior });
    else if (prior.signature !== next.signature) changes.push({ subject, change: "modify", compatibility: "breaking", current: next });
  }
  const effects = changes.map((change, index) => ({
    id: `effect-${String(index + 1).padStart(4, "0")}`,
    type: `${analyzer}.${change.current.kind}`,
    subject: change.subject,
    change: change.change,
    compatibility: change.compatibility,
    certainty: "proven",
    span: change.current.span,
    rationale: change.change === "add" ? `Public ${change.subject} was added.` : change.change === "remove" ? `Public ${change.subject} was removed.` : `Public ${change.subject} changed signature.`,
  }));
  const breaking = effects.filter((effect) => effect.compatibility === "breaking");
  return {
    status: breaking.length ? "blocked" : "ready",
    compatibility: {
      verdict: breaking.length ? "breaking" : "compatible",
      summary: breaking.length ? `${breaking.length} breaking public-surface effect${breaking.length === 1 ? "" : "s"} detected.` : "No breaking public-surface effect was detected within the certified parser contract.",
    },
    effects,
    uncertainty: [],
    counterexamples: breaking.map((effect) => ({ code: `breaking_${effect.change}`, subject: effect.subject, message: effect.rationale, span: effect.span })),
  };
}

export function analyzeRaw(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Analyzer input must be an object");
  const fields = ["analyzer", "beforePath", "beforeDigest", "beforeSource", "afterPath", "afterDigest", "afterSource"];
  if (Object.keys(input).some((key) => !fields.includes(key)) || fields.some((key) => typeof input[key] !== "string")) throw new Error("Analyzer input fields are invalid");
  if (!SUPPORTED.has(input.analyzer)) throw new Error("Unsupported analyzer id");
  if (Buffer.byteLength(input.beforeSource) > 256 * 1024 || Buffer.byteLength(input.afterSource) > 256 * 1024) throw new Error("Analyzer source exceeds 256 KiB");
  if (sha256(input.beforeSource) !== input.beforeDigest || sha256(input.afterSource) !== input.afterDigest) throw new Error("Analyzer source digest mismatch");
  const parser = parserFor(input.analyzer);
  try {
    const before = parser(input.beforeSource, "before");
    const after = parser(input.afterSource, "after");
    const unsupported = before.unsupported ?? after.unsupported;
    if (unsupported) {
      const source = before.unsupported ? input.beforeSource : input.afterSource;
      const sourceName = before.unsupported ? "before" : "after";
      return insufficient(input.analyzer, "unsupported_construct", unsupported.subject, `The certified ${input.analyzer} parser does not support ${unsupported.subject}.`, sourceSpan(sourceName, source, unsupported.token.start, unsupported.token.end));
    }
    if (input.analyzer === "cloudformation-cdk" && before.metadata?.sourceDigest && after.metadata?.sourceDigest && before.metadata.sourceDigest !== after.metadata.sourceDigest) {
      const token = after.metadata.sourceDigestToken;
      return insufficient(input.analyzer, "generated_template_drift", "Metadata.TugboatSourceDigest", "The synthesized template source digest changed; regenerate and bind the template before compatibility analysis.", sourceSpan("after", input.afterSource, token.start, token.end));
    }
    return compare(input.analyzer, before.symbols, after.symbols);
  } catch (error) {
    return insufficient(input.analyzer, "parse_error", input.afterPath, String(error.message ?? error), sourceSpan("after", input.afterSource, 0, Math.min(input.afterSource.length, 1)));
  }
}
