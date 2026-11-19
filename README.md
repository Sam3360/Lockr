# Lockr

Lockr is a local-first, command-line password manager for Node.js. It stores one versioned, encrypted vault on your computer and makes no network requests, telemetry, analytics, cloud sync, or accounts.

## Install

Requires Node.js 20 or newer. Until the package is published, clone this repository and run:

```bash
npm install
npm run build
npm link
lockr init
```

Install the published package with:

```bash
npm install -g @sam3360/lockr
lockr init
```

## Commands

```text
lockr init                     Create a vault
lockr status                   Check whether a vault exists
lockr add [service]            Add a credential interactively
lockr get <service>            Retrieve metadata; confirm before reveal
lockr list                     List credential names and usernames
lockr search <query>           Search service, username, category, and tags
lockr edit <service>           Edit interactively
lockr remove <service>         Confirm and remove a credential
lockr generate --length 24     Generate without storing a password
lockr backup [path]            Copy the encrypted vault
lockr restore <backup>         Authenticate, verify, and restore a backup
lockr lock                     Explain fresh-authentication CLI behavior
lockr change-master-password   Re-encrypt using a new master password
```

Passwords are never accepted as command-line arguments. The generator uses cryptographic randomness and does not save its output.

## Encryption and storage

The complete credential payload—including credential metadata—is JSON-encrypted using XChaCha20-Poly1305. A unique 16-byte salt and Argon2id parameters are stored in the outer vault envelope; Argon2id (64 MiB memory, 3 iterations, parallelism 1) derives a 32-byte encryption key from the master password. v1 accepts only those documented KDF parameters, preventing a modified vault from silently weakening them or requesting an unsafe amount of work. Each encryption receives a new 24-byte nonce. The vault includes an authenticated verification value, so an incorrect password, tampering, and corruption fail safely.

Vault files are versioned and written atomically with restrictive permissions where the platform supports them. Lockr refuses vault-file symbolic links. Default locations are `%APPDATA%\\Lockr` on Windows, `~/Library/Application Support/Lockr` on macOS, and `$XDG_DATA_HOME/lockr` (or `~/.local/share/lockr`) on Linux. Set `LOCKR_DATA_DIR` for a local test or a deliberately chosen location.

Backups are copies of the already encrypted vault; `lockr restore` authenticates the complete backup before replacing the current vault. A failed or malformed backup therefore leaves the current vault untouched. Keep the backup and master password separately.

## Security limits

The master password is never stored and cannot be recovered. Lockr accepts passwords of six to 1,024 characters, including spaces and punctuation, without character-type rules. Setup displays a guidance-only strength indicator and requires confirmation before accepting a weak password. Use a unique, long passphrase. Encryption at rest does not protect against malware, keyloggers, a compromised operating system, or an attacker reading an already-unlocked process. Each CLI invocation asks for the master password; there is no misleading persistent unlocked session, so `lockr lock` has no retained key to clear.

## Privacy

Lockr has no telemetry, analytics, crash uploads, tracking, automatic network requests, cloud sync, or account system. After npm installation it works offline.

## Development

```bash
npm run check
npm test
npm run build
```

Contributions should include focused tests and must not weaken authentication, encryption, filesystem safety, or privacy guarantees. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
