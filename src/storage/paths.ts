import { homedir, platform } from "node:os";
import { join } from "node:path";

export function appDataDir(): string {
  if (process.env.LOCKR_DATA_DIR) return process.env.LOCKR_DATA_DIR;
  if (platform() === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Lockr");
  if (platform() === "darwin") return join(homedir(), "Library", "Application Support", "Lockr");
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "lockr");
}
export function vaultPath(): string { return join(appDataDir(), "vault.lockr"); }
