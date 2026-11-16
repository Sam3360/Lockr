export interface Credential {
  id: string;
  service: string;
  username: string;
  password: string;
  website?: string;
  notes?: string;
  category?: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export interface VaultData {
  verification: "lockr-vault-verification-v1";
  createdAt: string;
  updatedAt: string;
  credentials: Credential[];
}

export interface VaultFile {
  format: "lockr-vault";
  version: 1;
  kdf: { algorithm: "argon2id"; salt: string; memoryCost: number; timeCost: number; parallelism: number; hashLength: number };
  cipher: { algorithm: "xchacha20-poly1305"; nonce: string; ciphertext: string };
}
