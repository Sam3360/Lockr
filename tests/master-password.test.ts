import test from "node:test";
import assert from "node:assert/strict";
import { passwordStrength, validateMasterPassword } from "../src/auth/master-password.js";

test("master password policy accepts six characters, spaces, and punctuation", () => {
  assert.equal(validateMasterPassword("abcdef"), undefined);
  assert.equal(validateMasterPassword("a space password"), undefined);
  assert.equal(validateMasterPassword("!@#$%^"), undefined);
  assert.match(validateMasterPassword("abcde") ?? "", /at least 6/);
});
test("strength is guidance rather than a validation requirement", () => {
  assert.equal(passwordStrength("abcdef"), "weak");
  assert.equal(validateMasterPassword("abcdef"), undefined);
});
