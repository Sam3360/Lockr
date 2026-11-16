import { mkdir, open, rename, lstat, chmod, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { errors } from "../errors.js";

async function assertNotLink(path: string): Promise<void> {
  try { if ((await lstat(path)).isSymbolicLink()) throw errors.symlink(); }
  catch (error: unknown) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}
export async function existsSafe(path: string): Promise<boolean> {
  await assertNotLink(path); try { await lstat(path); return true; } catch (error: unknown) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
}
export async function readSecure(path: string): Promise<Buffer> {
  await assertNotLink(path); const handle = await open(path, "r"); try { return await handle.readFile(); } finally { await handle.close(); }
}
export async function atomicWrite(path: string, data: Buffer): Promise<void> {
  const dir = dirname(path); await mkdir(dir, { recursive: true, mode: 0o700 }); await chmod(dir, 0o700).catch(() => undefined);
  await assertNotLink(path); const temp = join(dir, `.${randomBytes(12).toString("hex")}.tmp`);
  const handle = await open(temp, "wx", 0o600);
  try { await handle.writeFile(data); await handle.sync(); } finally { await handle.close(); }
  try { await rename(temp, path); await chmod(path, 0o600).catch(() => undefined); } catch (error) { await unlink(temp).catch(() => undefined); throw error; }
}
