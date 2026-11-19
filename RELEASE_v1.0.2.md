# Lockr v1.0.2

## Release summary

v1.0.2 is a maintenance release focused on vault reliability, safer cleanup after locking, and clearer installation guidance. It preserves the v1 encrypted vault format and does not add telemetry, networking, cloud sync, or accounts.

## Installation

Install globally with PowerShell:

```powershell
npm install -g --allow-scripts=argon2 @sam3360/lockr
```

`--allow-scripts=argon2` permits the native Argon2 dependency's installation script to run. This is required for the package's Argon2id implementation. The installed command is `lockr`.

## Changes

- Backup restoration verifies the complete encrypted backup before it replaces a vault.
- Vault add, edit, and remove operations retain a consistent in-memory state if persistence fails.
- Locking now clears credential data held by the active vault object on a best-effort basis.
- Credential service names are consistently validated, and edits cannot introduce duplicates.
- Regression coverage now includes malformed backups, restore recovery, password rotation, input validation, v1 envelope compatibility, and locking cleanup.

## Verification

Run before publishing:

```powershell
npm run check
npm test
npm run build
npm audit
npm pack --dry-run
```

No release command in this repository publishes to npm or GitHub automatically.

## Known limits

This project has not received an independent security audit. Validate interactive terminal behavior and Linux/macOS support in their native environments before relying on a release for important credentials.
