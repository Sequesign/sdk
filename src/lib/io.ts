import { mkdir, readFile, readdir, rm, writeFile, cp } from "node:fs/promises";
import path from "node:path";
export async function resetDir(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
}
export async function ensureDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
}
export async function writeJson(filePath: string, value: unknown): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, JSON.stringify(value, null, 2) + "\n", "utf8");
}
export async function writeText(filePath: string, value: string): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, value, "utf8");
}
export async function readJson<T = unknown>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}
export async function writeJsonl(filePath: string, values: unknown[]): Promise<void> {
  await ensureDir(path.dirname(filePath));
  await writeFile(filePath, values.map((v) => JSON.stringify(v)).join("\n") + "\n", "utf8");
}
export async function readJsonl<T = unknown>(filePath: string): Promise<T[]> {
  const text = await readFile(filePath, "utf8");
  return text
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as T);
}
export async function listJsonFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  return entries
    .filter((e) => e.isFile() && e.name.endsWith(".json"))
    .map((e) => path.join(dir, e.name))
    .sort();
}
export async function copyDir(from: string, to: string): Promise<void> {
  await rm(to, { recursive: true, force: true });
  await cp(from, to, { recursive: true });
}
