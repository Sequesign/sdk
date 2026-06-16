import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import path from "node:path";

function findProjectRoot(start: string): string {
  // In a browser, there is no filesystem and no project root. The
  // browser verifier reaches this path because src/lib/verify.ts is
  // reused unchanged on the verifier UI; the verifier's node:fs shim
  // routes every read to an in-memory virtual-fs and a
  // registry-prefix fetch path, neither of which depends on
  // PROJECT_ROOT pointing at a real filesystem location.
  //
  // The sentinel must be "", not "/". The shim's fetchRegistryFile
  // checks startsWith("registry/") / "schemas/" / "profiles/" on a
  // normalized path, and that normalization preserves a leading
  // slash. With PROJECT_ROOT="/" the helpers below produce
  // "/registry/manifest.json", which the prefix check rejects and
  // schema/profile fetches silently fail. With PROJECT_ROOT=""
  // path.join("", "registry", "manifest.json") yields
  // "registry/manifest.json", which the prefix check accepts.
  //
  // In Node, typeof process === "undefined" is false, so this guard
  // is dead code and the original directory walk runs unchanged.
  if (typeof process === "undefined") {
    return "";
  }
  let current = path.resolve(start);
  while (true) {
    if (existsSync(path.join(current, "package.json"))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error(
        `Sequesign: unable to locate project root above ${start}; expected a package.json on the path.`
      );
    }
    current = parent;
  }
}

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

// Absolute path to the repository root, resolved by walking up from this
// module's directory until a package.json is found. Resolving this way
// makes every helper below independent of process.cwd(), which differs
// between local dev (repo root) and Railway (whatever the runtime sets).
export const PROJECT_ROOT: string = findProjectRoot(moduleDir);

export function registryPath(...parts: string[]): string {
  // Honor an opt-in override of the registry directory (the folder that
  // holds manifest.json). Default is PROJECT_ROOT/registry. Test and demo
  // writers that register dynamically-created schemas set
  // SEQUESIGN_REGISTRY_DIR to a temp copy so they never mutate the
  // tracked registry/manifest.json (a production asset the broker and
  // verifier read). Read at call time so a writer can seed and set it
  // just before use. In the browser, process is the bundler polyfill (or
  // undefined) and the var is never set, so the default branch runs and
  // PROJECT_ROOT="" yields the "registry/..." prefix the verifier shim
  // expects.
  const override =
    typeof process !== "undefined" ? process.env.SEQUESIGN_REGISTRY_DIR : undefined;
  if (override && override.length > 0) {
    return path.join(override, ...parts);
  }
  return path.join(PROJECT_ROOT, "registry", ...parts);
}

export function profilesPath(...parts: string[]): string {
  return path.join(PROJECT_ROOT, "profiles", ...parts);
}

export function schemasPath(...parts: string[]): string {
  return path.join(PROJECT_ROOT, "schemas", ...parts);
}

export function demosPath(...parts: string[]): string {
  return path.join(PROJECT_ROOT, "demos", ...parts);
}

export function outPath(...parts: string[]): string {
  return path.join(PROJECT_ROOT, "out", ...parts);
}

export function srcPath(...parts: string[]): string {
  return path.join(PROJECT_ROOT, "src", ...parts);
}

// Resolve any repo-relative asset reference (for example, the schema and
// profile `path` fields embedded inside registry/manifest.json) against
// the project root. Absolute paths are returned unchanged.
export function resolveAsset(file: string): string {
  return path.isAbsolute(file) ? file : path.join(PROJECT_ROOT, file);
}
