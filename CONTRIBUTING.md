# Contributing

Thanks for helping improve CIphera.

## Before opening a pull request

1. Fork the repository and create a focused branch.
2. Keep changes small enough to review.
3. Never commit real vaults, passwords, API keys, keyfiles, tokens or breach data.
4. Run:

```bash
cargo fmt --all
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

5. Update documentation when behavior changes.

## Security-sensitive changes

Changes to cryptography, KDF parameters, serialization, keyfiles, backup/restore, clipboard behavior or breach-provider requests require extra review.

Do not replace established cryptographic primitives with custom crypto.

## Style

CIphera intentionally uses a compact classic terminal UI. Avoid turning it into a pseudo-desktop interface or adding unnecessary visual clutter.

## Issues

Public issues are appropriate for normal bugs and feature requests. Security vulnerabilities should follow `SECURITY.md`.
