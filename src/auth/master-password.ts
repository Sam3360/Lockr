export const MIN_MASTER_PASSWORD_LENGTH = 6;
export const MAX_MASTER_PASSWORD_LENGTH = 1024;

export type PasswordStrength = "weak" | "fair" | "strong";

export function validateMasterPassword(password: string): string | undefined {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) return `Master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters.`;
  if (password.length > MAX_MASTER_PASSWORD_LENGTH) return `Master password must be no more than ${MAX_MASTER_PASSWORD_LENGTH} characters.`;
  return undefined;
}

// Guidance only: this is not an entropy claim or a policy gate. Passphrases are welcome.
export function passwordStrength(password: string): PasswordStrength {
  const unique = new Set(password).size;
  if (password.length >= 16 || (password.length >= 12 && unique >= 8)) return "strong";
  if (password.length >= 10 || (password.length >= 8 && unique >= 5)) return "fair";
  return "weak";
}
