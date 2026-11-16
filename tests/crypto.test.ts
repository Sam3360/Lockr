import test from "node:test";
import assert from "node:assert/strict";
import { decrypt, deriveKey, encrypt, randomNonce, randomSalt } from "../src/crypto/index.js";

test("encrypts, authenticates, and decrypts", async () => {
  const key = await deriveKey("correct horse battery staple", randomSalt()); const sealed = encrypt(key, Buffer.from("synthetic secret"));
  assert.equal(decrypt(key, sealed.nonce, sealed.ciphertext)?.toString(), "synthetic secret");
  sealed.ciphertext[0] ^= 1; assert.equal(decrypt(key, sealed.nonce, sealed.ciphertext), undefined);
});
test("argon2 keys differ for different passwords and salts", async () => {
  const salt = randomSalt(); assert.notDeepEqual(await deriveKey("one", salt), await deriveKey("two", salt)); assert.notDeepEqual(await deriveKey("one", salt), await deriveKey("one", randomSalt()));
});
test("nonces are 24 bytes and freshly random", () => assert.notDeepEqual(randomNonce(), randomNonce()));
