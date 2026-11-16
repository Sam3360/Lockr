import { randomInt } from "node:crypto";

export interface PasswordOptions { length: number; upper?: boolean; lower?: boolean; numbers?: boolean; symbols?: boolean; }
const SETS = { upper: "ABCDEFGHJKLMNPQRSTUVWXYZ", lower: "abcdefghijkmnopqrstuvwxyz", numbers: "23456789", symbols: "!@#$%^&*_-+=?" };
export function generatePassword(options: PasswordOptions): string {
  if (!Number.isInteger(options.length) || options.length < 8 || options.length > 256) throw new Error("Password length must be an integer between 8 and 256.");
  const selected = (Object.keys(SETS) as Array<keyof typeof SETS>).filter(k => options[k] !== false);
  if (!selected.length) throw new Error("Choose at least one character set.");
  const alphabet = selected.map(k => SETS[k]).join(""); const chars = Array.from({ length: options.length }, () => alphabet[randomInt(alphabet.length)]);
  // Ensure every enabled group is represented before shuffling with unbiased randomInt.
  selected.forEach((key, i) => { chars[i] = SETS[key][randomInt(SETS[key].length)]; });
  for (let i = chars.length - 1; i > 0; i--) { const j = randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join("");
}
