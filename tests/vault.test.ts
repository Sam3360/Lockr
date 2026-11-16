import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/vault/vault.js";

async function path(): Promise<string> { return join(await mkdtemp(join(tmpdir(), "lockr-test-")), "vault.lockr"); }
const example = { service: "Example", username: "tester", password: "not-a-real-secret", tags: ["test"] };
test("creates, persists, updates and removes credentials", async () => {
  const p = await path(); const custom = await Vault.create("long test password", p); await custom.add(example); custom.lock();
  const reopened = await Vault.unlock("long test password", p); assert.equal(reopened.find("example")?.username, "tester"); await reopened.update("example", { username: "changed" }); await reopened.remove("example"); assert.equal(reopened.data.credentials.length, 0); reopened.lock();
});
test("rejects wrong passwords and tampered ciphertext", async () => {
  const p = await path(), v = await Vault.create("long test password", p); v.lock(); await assert.rejects(() => Vault.unlock("wrong password", p));
  const raw = await readFile(p); raw[raw.length - 2] ^= 1; await writeFile(p, raw); await assert.rejects(() => Vault.unlock("long test password", p));
});
test("accepts six-character, spaced, and punctuation master passwords", async () => {
  for (const password of ["abcdef", "six words pass", "!@#$%^&*"]) { const p = await path(); const v = await Vault.create(password, p); v.lock(); const reopened = await Vault.unlock(password, p); assert.equal(reopened.data.credentials.length, 0); reopened.lock(); }
});
test("rejects master passwords shorter than six characters", async () => {
  const p = await path(); await assert.rejects(() => Vault.create("short", p));
});
test("changes the master password and invalidates the old one", async () => {
  const p = await path(), v = await Vault.create("old pass", p); await v.add(example); await v.changeMasterPassword("new pass!"); v.lock(); await assert.rejects(() => Vault.unlock("old pass", p)); const reopened = await Vault.unlock("new pass!", p); assert.equal(reopened.find("Example")?.username, "tester"); reopened.lock();
});
test("restores an authenticated encrypted backup after password rotation", async () => {
  const p = await path(), backup = `${p}.backup`, v = await Vault.create("old pass", p);
  await v.add(example); await v.changeMasterPassword("new pass!"); v.lock();
  const backupBytes = await readFile(p); await writeFile(backup, backupBytes);
  const checked = await Vault.unlockRaw("new pass!", await readFile(backup), backup); checked.lock();
  const modified = await Vault.unlock("new pass!", p); await modified.remove("Example"); modified.lock();
  await writeFile(p, backupBytes);
  const restored = await Vault.unlock("new pass!", p); assert.equal(restored.find("Example")?.password, "not-a-real-secret"); restored.lock();
});
