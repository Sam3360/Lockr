import argon2 from "argon2";
import { XChaCha20Poly1305 } from "@stablelib/xchacha20poly1305";
import { randomBytes } from "node:crypto";

export const KDF_DEFAULTS = { memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32 } as const;
export const SALT_BYTES = 16;
export const NONCE_BYTES = 24;

export async function deriveKey(password: string, salt: Buffer, params = KDF_DEFAULTS): Promise<Buffer> {
  return Buffer.from(await argon2.hash(password, { type: argon2.argon2id, salt, raw: true, ...params }));
}
export function randomSalt(): Buffer { return randomBytes(SALT_BYTES); }
export function randomNonce(): Buffer { return randomBytes(NONCE_BYTES); }
export function encrypt(key: Uint8Array, plaintext: Uint8Array, nonce = randomNonce()): { nonce: Buffer; ciphertext: Buffer } {
  const cipher = new XChaCha20Poly1305(key);
  return { nonce, ciphertext: Buffer.from(cipher.seal(nonce, plaintext)) };
}
export function decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Buffer | undefined {
  if (nonce.length !== NONCE_BYTES) return undefined;
  const cipher = new XChaCha20Poly1305(key);
  const plaintext = cipher.open(nonce, ciphertext);
  return plaintext ? Buffer.from(plaintext) : undefined;
}
export function wipe(value: Uint8Array): void { value.fill(0); }
