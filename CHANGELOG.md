# Changelog

All notable CIphera changes should be documented here.

## [Unreleased]

- Prepare public beta repository.
- Add CI workflow and repository templates.
- Add security policy and threat-model documentation.
- Preserve previous keyfile during keyfile rotation.
- Add basic unit tests for password generation, tag parsing, URL encoding and security defaults.

## [1.3.0] - 2026-08-16

### Added
- Security menu.
- Hardened Argon2id defaults for new vaults.
- Argon2id benchmark/tuning.
- Optional 256-bit keyfile.
- Vault integrity and permission checks.
- Encrypted backup restore flow.
- Opt-in email breach scanner.
- XposedOrNot and LeakCheck Public provider integrations.
- Optional HIBP integration using `HIBP_API_KEY`.
- Normalized breach tree and JSON views.

### Security
- New master passwords require at least 16 characters.
- Vault, backup and keyfile permissions are restricted.
- Sensitive buffers are zeroized where practical.
