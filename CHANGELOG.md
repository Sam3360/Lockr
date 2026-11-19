# Changelog

## 1.0.1 - 2026-11-19

- Added production-path backup and restore helpers, including authenticated backup verification before replacement.
- Made vault mutations transactional in memory when a vault write fails.
- Reject invalid and duplicate service names consistently, including during edits.
- Added regression coverage for malformed backups, backup recovery, v1 vault compatibility, invalid input, duplicate/missing credentials, and master-password rotation.
- Updated installation instructions for the scoped npm package.

## 1.0.0 - 2026-11-16

- Initial usable release: encrypted local vaults, credential management, search, categories and tags, generator, encrypted backups, restoration, tests, and documentation.
- Security hardening: six-character minimum master-password policy with guidance-only strength warnings, master-password rotation, strict v1 KDF/envelope validation, and race-safe backup restoration.
