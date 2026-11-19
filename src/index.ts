#!/usr/bin/env node
import { Command } from "commander";
import { resolve } from "node:path";
import { Vault } from "./vault/vault.js";
import { appDataDir, vaultPath } from "./storage/paths.js";
import { existsSafe } from "./storage/file.js";
import { createEncryptedBackup, restoreEncryptedBackup } from "./vault/backup.js";
import { authenticate, confirm, credentialInput, masterPassword } from "./prompts/index.js";
import { passwordStrength, validateMasterPassword } from "./auth/master-password.js";
import { generatePassword } from "./passwords/generate.js";
import { LockrError } from "./errors.js";

const program = new Command();
program.name("lockr").description("Local-first encrypted password manager").version("1.0.2");
async function unlocked(): Promise<Vault> { return Vault.unlock(await authenticate()); }
async function chooseMasterPassword(): Promise<string> {
  const first = await masterPassword("Create master password:"); const invalid = validateMasterPassword(first); if (invalid) throw new Error(invalid);
  const strength = passwordStrength(first); console.log(`Password strength: ${strength}.`);
  if (strength === "weak" && !await confirm({ message: "This password may be easy to guess. Use it anyway?", default: false })) throw new Error("Master-password setup cancelled.");
  if (first !== await masterPassword("Confirm master password:")) throw new Error("Master passwords did not match."); return first;
}
function printCredential(c: { service: string; username: string; password: string; website?: string; notes?: string; category?: string; tags: string[] }, reveal = false): void {
  console.log(`\nService: ${c.service}\nUsername: ${c.username}\nPassword: ${reveal ? c.password : "[hidden]"}`);
  if (c.website) console.log(`Website: ${c.website}`); if (c.category) console.log(`Category: ${c.category}`); if (c.tags.length) console.log(`Tags: ${c.tags.join(", ")}`); if (c.notes) console.log(`Notes: ${c.notes}`);
}
program.command("init").description("Create a new encrypted vault").action(async () => {
  if (await existsSafe(vaultPath())) throw new Error("A vault already exists; Lockr will not overwrite it.");
  console.log("Welcome to Lockr. Your master password cannot be recovered if forgotten."); const first = await chooseMasterPassword();
  const v = await Vault.create(first); v.lock(); console.log("Vault successfully created.");
});
program.command("status").description("Show local vault status").action(async () => console.log(await existsSafe(vaultPath()) ? `Vault found at ${vaultPath()} (encrypted; ${appDataDir()})` : "No vault found."));
program.command("lock").description("Explain CLI locking behavior").action(() => console.log("Each Lockr command runs in a separate process and requires fresh authentication. No unlocked session is retained."));
program.command("change-master-password").description("Change the master password and re-encrypt the vault").action(async () => { const v = await unlocked(); try { const next = await chooseMasterPassword(); await v.changeMasterPassword(next); console.log("Master password changed."); } finally { v.lock(); } });
program.command("add [service]").description("Add a credential").action(async (service?: string) => { const v = await unlocked(); try { const c = await credentialInput(); if (service) c.service = service; await v.add(c); console.log(`Saved ${c.service}.`); } finally { v.lock(); } });
program.command("get <service>").description("Retrieve a credential").action(async (service: string) => { const v = await unlocked(); try { const c = v.find(service); if (!c) throw new Error("No matching credential was found."); printCredential(c); if (await confirm({ message: "Reveal password?", default: false })) printCredential(c, true); } finally { v.lock(); } });
program.command("list").description("List credentials without passwords").action(async () => { const v = await unlocked(); try { if (!v.data.credentials.length) console.log("Your vault is empty."); else v.data.credentials.forEach((c, i) => console.log(`${i + 1}. ${c.service} (${c.username})`)); console.log(`${v.data.credentials.length} credential(s) found.`); } finally { v.lock(); } });
program.command("search <query>").description("Search service, username, category, or tags").action(async query => { const v = await unlocked(); try { const matches = v.search(query); matches.forEach(c => console.log(`${c.service} (${c.username})${c.tags.length ? ` [${c.tags.join(", ")}]` : ""}`)); console.log(`${matches.length} match(es) found.`); } finally { v.lock(); } });
program.command("edit <service>").description("Edit a credential interactively").action(async service => { const v = await unlocked(); try { const existing = v.find(service); if (!existing) throw new Error("No matching credential was found."); const input = await credentialInput(existing); await v.update(service, input); console.log(`Updated ${input.service}.`); } finally { v.lock(); } });
program.command("remove <service>").description("Remove a credential").action(async service => { const v = await unlocked(); try { if (await confirm({ message: `Permanently remove ${service}?`, default: false })) { await v.remove(service); console.log("Credential removed."); } else console.log("Cancelled."); } finally { v.lock(); } });
program.command("generate").description("Generate a password without storing it").option("-l, --length <number>", "password length", "24").option("--no-upper", "exclude uppercase").option("--no-lower", "exclude lowercase").option("--no-numbers", "exclude numbers").option("--no-symbols", "exclude symbols").action(async options => { const generated = generatePassword({ length: Number(options.length), upper: options.upper, lower: options.lower, numbers: options.numbers, symbols: options.symbols }); if (await confirm({ message: "Reveal generated password?", default: true })) console.log(generated); else console.log("Password generated but not displayed."); });
program.command("backup [path]").description("Copy the encrypted vault to a backup file").action(async path => { const v = await unlocked(); try { const target = await createEncryptedBackup(vaultPath(), path || `lockr-backup-${new Date().toISOString().slice(0, 10)}.lockr`); console.log(`Encrypted backup created: ${target}`); } finally { v.lock(); } });
program.command("restore <backup>").description("Restore an encrypted backup after verification").action(async backup => { const password = await authenticate(); if (!await confirm({ message: `Replace the current vault with ${resolve(backup)}?`, default: false })) return console.log("Cancelled."); const restored = await restoreEncryptedBackup(password, backup, vaultPath()); console.log(`Backup restored from ${restored.name}.`); });
program.action(async () => { if (await existsSafe(vaultPath())) console.log("Lockr vault found. Run 'lockr --help' to see commands."); else await program.parseAsync([process.argv[0], process.argv[1], "init"]); });
program.configureOutput({ writeErr: str => process.stderr.write(str) });
program.parseAsync().catch(error => { const safe = error instanceof LockrError ? error.message : error instanceof Error ? error.message : "Lockr failed safely."; console.error(`Error: ${safe}`); process.exitCode = 1; });
