// Writes web/openapi.json from the server's FastAPI app (no server needs to be running).
// Works on Windows (.venv\Scripts\python.exe) and Linux/macOS (.venv/bin/python).
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const candidates = process.platform === "win32"
  ? [join(repo, ".venv", "Scripts", "python.exe")]
  : [join(repo, ".venv", "bin", "python")];
const python = process.env.SENTINEL_PYTHON ?? candidates.find((p) => existsSync(p)) ?? "python";
const dataDir = join(tmpdir(), "sentinel-openapi");
mkdirSync(dataDir, { recursive: true });

const code = [
  "import json",
  "from sentinel_server.app import create_app",
  "print(json.dumps(create_app(start_background=False, run_migrations=False).openapi()))",
].join("; ");

const out = execFileSync(python, ["-c", code], {
  cwd: repo,
  env: { ...process.env, SENTINEL_MODE: "test", SENTINEL_DATA_DIR: dataDir },
  encoding: "utf-8",
  maxBuffer: 64 * 1024 * 1024,
});
// The app may print log lines before the JSON; keep only the last line.
const json = out.trim().split(/\r?\n/).pop() ?? "";
JSON.parse(json);
writeFileSync(join(here, "..", "openapi.json"), json + "\n", "utf-8");
console.log("Wrote web/openapi.json");
