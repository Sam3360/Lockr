import { randomUUID } from "node:crypto";
import { decrypt, deriveKey, encrypt, KDF_DEFAULTS, randomSalt, type KdfParams, wipe } from "../crypto/index.js";
import { errors } from "../errors.js";
import { atomicWrite, existsSafe, readSecure } from "../storage/file.js";
import { vaultPath } from "../storage/paths.js";
import { validateMasterPassword } from "../auth/master-password.js";
import type { Credential, VaultData, VaultFile } from "../types.js";

const encode = (v: Uint8Array) => Buffer.from(v).toString("base64");
const decode = (v: string) => Buffer.from(v, "base64");
function parseFile(raw: Buffer): VaultFile { try { const f = JSON.parse(raw.toString("utf8")); if (f?.format !== "lockr-vault") throw errors.corrupt(); if (f.version !== 1) throw errors.unsupported(); if (f.kdf?.algorithm !== "argon2id" || f.cipher?.algorithm !== "xchacha20-poly1305") throw errors.corrupt(); const { memoryCost, timeCost, parallelism, hashLength } = f.kdf; if (memoryCost !== KDF_DEFAULTS.memoryCost || timeCost !== KDF_DEFAULTS.timeCost || parallelism !== KDF_DEFAULTS.parallelism || hashLength !== KDF_DEFAULTS.hashLength) throw errors.corrupt(); if (decode(f.kdf.salt).length !== 16 || decode(f.cipher.nonce).length !== 24 || decode(f.cipher.ciphertext).length < 16) throw errors.corrupt(); return f; } catch (e) { if (e instanceof Error && "code" in e) throw e; throw errors.corrupt(); } }
function validate(data: unknown): VaultData { const d = data as VaultData; if (!d || d.verification !== "lockr-vault-verification-v1" || !Array.isArray(d.credentials)) throw errors.auth(); return d; }
function validateCredential(input: Pick<Credential, "service">): void { if (!input.service || input.service.trim().length > 256) throw errors.invalidCredential(); }

export class Vault {
  private constructor(private readonly path: string, private key: Buffer, private salt: Buffer, private readonly kdf: KdfParams, public data: VaultData) {}
  static async create(password: string, path = vaultPath()): Promise<Vault> {
    const invalid = validateMasterPassword(password); if (invalid) throw errors.invalidMasterPassword(invalid);
    if (await existsSafe(path)) throw errors.exists();
    const salt = randomSalt(), key = await deriveKey(password, salt), now = new Date().toISOString();
    const data: VaultData = { verification: "lockr-vault-verification-v1", createdAt: now, updatedAt: now, credentials: [] };
    const vault = new Vault(path, key, salt, KDF_DEFAULTS, data); try { await vault.save(); return vault; } catch (error) { vault.lock(); throw error; }
  }
  static async unlock(password: string, path = vaultPath()): Promise<Vault> {
    if (!await existsSafe(path)) throw errors.noVault(); return this.unlockRaw(password, await readSecure(path), path);
  }
  static async unlockRaw(password: string, raw: Buffer, path = vaultPath()): Promise<Vault> {
    const file = parseFile(raw);
    const salt = decode(file.kdf.salt);
    const { memoryCost, timeCost, parallelism, hashLength } = file.kdf;
    const key = await deriveKey(password, salt, { memoryCost, timeCost, parallelism, hashLength });
    let plain: Buffer | undefined;
    try { plain = decrypt(key, decode(file.cipher.nonce), decode(file.cipher.ciphertext)); if (!plain) throw errors.auth(); const data = validate(JSON.parse(plain.toString("utf8"))); return new Vault(path, key, salt, { memoryCost, timeCost, parallelism, hashLength }, data); } catch (e) { wipe(key); if (e instanceof Error && "code" in e) throw e; throw errors.auth(); } finally { if (plain) wipe(plain); }
  }
  private async write(key: Buffer, salt: Buffer): Promise<void> {
    this.data.updatedAt = new Date().toISOString(); const plain = Buffer.from(JSON.stringify(this.data)); const sealed = encrypt(key, plain); wipe(plain);
    const file: VaultFile = { format: "lockr-vault", version: 1, kdf: { algorithm: "argon2id", salt: encode(salt), ...this.kdf }, cipher: { algorithm: "xchacha20-poly1305", nonce: encode(sealed.nonce), ciphertext: encode(sealed.ciphertext) } };
    await atomicWrite(this.path, Buffer.from(JSON.stringify(file)));
  }
  private async save(): Promise<void> { await this.write(this.key, this.salt); }
  async changeMasterPassword(newPassword: string): Promise<void> { const invalid = validateMasterPassword(newPassword); if (invalid) throw errors.invalidMasterPassword(invalid); const newSalt = randomSalt(), newKey = await deriveKey(newPassword, newSalt, this.kdf); try { await this.write(newKey, newSalt); } catch (error) { wipe(newKey); wipe(newSalt); throw error; } wipe(this.key); wipe(this.salt); this.key = newKey; this.salt = newSalt; }
  async add(input: Omit<Credential, "id" | "createdAt" | "updatedAt">): Promise<Credential> { validateCredential(input); if (this.data.credentials.some(x => x.service.toLocaleLowerCase() === input.service.toLocaleLowerCase())) throw errors.duplicate(); const now = new Date().toISOString(); const c = { ...input, id: randomUUID(), createdAt: now, updatedAt: now }; this.data.credentials.push(c); try { await this.save(); return c; } catch (error) { this.data.credentials.pop(); throw error; } }
  find(query: string): Credential | undefined { const q = query.toLocaleLowerCase(); return this.data.credentials.find(c => c.service.toLocaleLowerCase() === q); }
  search(query: string): Credential[] { const q = query.toLocaleLowerCase(); return this.data.credentials.filter(c => [c.service, c.username, c.category ?? "", ...c.tags].some(v => v.toLocaleLowerCase().includes(q))); }
  async update(service: string, changes: Partial<Omit<Credential, "id" | "createdAt">>): Promise<Credential> { const c = this.find(service); if (!c) throw errors.missing(); if (changes.service !== undefined) { validateCredential({ service: changes.service }); if (this.data.credentials.some(x => x !== c && x.service.toLocaleLowerCase() === changes.service!.toLocaleLowerCase())) throw errors.duplicate(); } const before = { ...c, tags: [...c.tags] }; Object.assign(c, changes, { updatedAt: new Date().toISOString() }); try { await this.save(); return c; } catch (error) { Object.assign(c, before); throw error; } }
  async remove(service: string): Promise<void> { const index = this.data.credentials.findIndex(c => c.service.toLocaleLowerCase() === service.toLocaleLowerCase()); if (index < 0) throw errors.missing(); const [removed] = this.data.credentials.splice(index, 1); try { await this.save(); } catch (error) { this.data.credentials.splice(index, 0, removed); throw error; } }
  lock(): void { wipe(this.key); wipe(this.salt); this.key = Buffer.alloc(0); this.salt = Buffer.alloc(0); this.data.credentials.forEach(c => { c.service = ""; c.username = ""; c.password = ""; c.website = ""; c.notes = ""; c.category = ""; c.tags = []; }); this.data.credentials.length = 0; }
}
