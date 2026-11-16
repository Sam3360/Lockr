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
