export class LockrError extends Error {
  constructor(message: string, public readonly code: string) { super(message); }
}
export const errors = {
  noVault: () => new LockrError("No vault exists. Run 'lockr init' to create one.", "NO_VAULT"),
  exists: () => new LockrError("A vault already exists; Lockr will not overwrite it.", "VAULT_EXISTS"),
  auth: () => new LockrError("Unable to unlock vault. Check the master password or vault integrity.", "AUTH_FAILED"),
  corrupt: () => new LockrError("Vault is corrupted or has an invalid format.", "CORRUPT_VAULT"),
  unsupported: () => new LockrError("This vault version is not supported by this Lockr version.", "UNSUPPORTED_VAULT"),
  symlink: () => new LockrError("Refusing to access a vault through a symbolic link.", "UNSAFE_PATH"),
  invalidMasterPassword: (message: string) => new LockrError(message, "INVALID_MASTER_PASSWORD"),
  invalidCredential: () => new LockrError("Service name is required and must be 256 characters or fewer.", "INVALID_CREDENTIAL"),
  duplicate: () => new LockrError("A credential with that service name already exists.", "DUPLICATE"),
  missing: () => new LockrError("No matching credential was found.", "MISSING")
};
