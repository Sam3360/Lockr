import { randomUUID } from "node:crypto";
import { decrypt, deriveKey, encrypt, KDF_DEFAULTS, randomSalt, wipe } from "../crypto/index.js";
import { errors } from "../errors.js";
import { atomicWrite, existsSafe, readSecure } from "../storage/file.js";
import { vaultPath } from "../storage/paths.js";
import type { Credential, VaultData, VaultFile } from "../types.js";

const encode = (v: Uint8Array) => Buffer.from(v).toString("base64");
const decode = (v: string) => Buffer.from(v, "base64");
function parseFile(raw: Buffer): VaultFile { try { const f = JSON.parse(raw.toString("utf8")); if (f?.format !== "lockr-vault") throw errors.corrupt(); if (f.version !== 1) throw errors.unsupported(); if (f.kdf?.algorithm !== "argon2id" || f.cipher?.algorithm !== "xchacha20-poly1305") throw errors.corrupt(); return f; } catch (e) { if (e instanceof Error && "code" in e) throw e; throw errors.corrupt(); } }
function validate(data: unknown): VaultData { const d = data as VaultData; if (!d || d.verification !== "lockr-vault-verification-v1" || !Array.isArray(d.credentials)) throw errors.auth(); return d; }

export class Vault {
  private constructor(private readonly path: string, private key: Buffer, public data: VaultData) {}
  static async create(password: string, path = vaultPath()): Promise<Vault> {
    if (await existsSafe(path)) throw errors.exists();
    const salt = randomSalt(), key = await deriveKey(password, salt), now = new Date().toISOString();
    const data: VaultData = { verification: "lockr-vault-verification-v1", createdAt: now, updatedAt: now, credentials: [] };
    const vault = new Vault(path, key, data); await vault.save(salt); return vault;
  }
  static async unlock(password: string, path = vaultPath()): Promise<Vault> {
    if (!await existsSafe(path)) throw errors.noVault(); const file = parseFile(await readSecure(path));
    const salt = decode(file.kdf.salt), key = await deriveKey(password, salt, file.kdf);
    try { const plain = decrypt(key, decode(file.cipher.nonce), decode(file.cipher.ciphertext)); if (!plain) throw errors.auth(); const data = validate(JSON.parse(plain.toString("utf8"))); wipe(plain); return new Vault(path, key, data); } catch (e) { wipe(key); if (e instanceof Error && "code" in e) throw e; throw errors.auth(); }
  }
  private async save(existingSalt?: Buffer): Promise<void> {
    const salt = existingSalt ?? decode(parseFile(await readSecure(this.path)).kdf.salt); this.data.updatedAt = new Date().toISOString();
    const plain = Buffer.from(JSON.stringify(this.data)); const sealed = encrypt(this.key, plain); wipe(plain);
    const file: VaultFile = { format: "lockr-vault", version: 1, kdf: { algorithm: "argon2id", salt: encode(salt), ...KDF_DEFAULTS }, cipher: { algorithm: "xchacha20-poly1305", nonce: encode(sealed.nonce), ciphertext: encode(sealed.ciphertext) } };
    await atomicWrite(this.path, Buffer.from(JSON.stringify(file)));
  }
  async add(input: Omit<Credential, "id" | "createdAt" | "updatedAt">): Promise<Credential> { if (this.data.credentials.some(x => x.service.toLocaleLowerCase() === input.service.toLocaleLowerCase())) throw errors.duplicate(); const now = new Date().toISOString(); const c = { ...input, id: randomUUID(), createdAt: now, updatedAt: now }; this.data.credentials.push(c); await this.save(); return c; }
  find(query: string): Credential | undefined { const q = query.toLocaleLowerCase(); return this.data.credentials.find(c => c.service.toLocaleLowerCase() === q); }
  search(query: string): Credential[] { const q = query.toLocaleLowerCase(); return this.data.credentials.filter(c => [c.service, c.username, c.category ?? "", ...c.tags].some(v => v.toLocaleLowerCase().includes(q))); }
  async update(service: string, changes: Partial<Omit<Credential, "id" | "createdAt">>): Promise<Credential> { const c = this.find(service); if (!c) throw errors.missing(); Object.assign(c, changes, { updatedAt: new Date().toISOString() }); await this.save(); return c; }
  async remove(service: string): Promise<void> { const index = this.data.credentials.findIndex(c => c.service.toLocaleLowerCase() === service.toLocaleLowerCase()); if (index < 0) throw errors.missing(); this.data.credentials.splice(index, 1); await this.save(); }
  lock(): void { wipe(this.key); this.key = Buffer.alloc(0); this.data.credentials.forEach(c => { c.password = ""; c.notes = ""; }); }
}
