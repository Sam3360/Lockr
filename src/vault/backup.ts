import { basename, resolve } from "node:path";
import { errors } from "../errors.js";
import { atomicWrite, existsSafe, readSecure } from "../storage/file.js";
import { Vault } from "./vault.js";

export async function createEncryptedBackup(source: string, destination: string): Promise<string> {
  const target = resolve(destination);
  if (await existsSafe(target)) throw errors.exists();
  await atomicWrite(target, await readSecure(source));
  return target;
}

export async function verifyEncryptedBackup(password: string, source: string): Promise<Buffer> {
  const resolved = resolve(source), raw = await readSecure(resolved);
  const vault = await Vault.unlockRaw(password, raw, resolved);
  vault.lock();
  return raw;
}

export async function restoreEncryptedBackup(password: string, source: string, destination: string): Promise<{ name: string }> {
  const raw = await verifyEncryptedBackup(password, source);
  await atomicWrite(destination, raw);
  return { name: basename(resolve(source)) };
}
