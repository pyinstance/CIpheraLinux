# CIphera

> Local-first encrypted CLI password manager for Linux.

**Status:** Public beta. CIphera is usable and designed with security in mind, but it has **not undergone an independent security audit**. Keep another recovery method for credentials you cannot afford to lose.

```text
╭─ VAULT STATUS ───────────────────────────────────────────────╮
│ ● UNLOCKED    2 entries    Clipboard: 15s    Health: 1/0    │
╰──────────────────────────────────────────────────────────────╯
```

## Install globally

Install CIphera system-wide:

```bash
curl -fsSL https://raw.githubusercontent.com/pyinstance/CIpheraLinux/main/install.sh | bash
```


CIphera is a keyboard-first Linux password manager built around a simple boxed terminal interface rather than a desktop GUI.

## Highlights

- Local encrypted vault — no CIphera cloud account
- XChaCha20-Poly1305 authenticated encryption
- Argon2id master-key derivation
- Hardened new-vault default: 128 MiB / 4 iterations / 1 lane
- 16-character minimum master password for newly created vaults
- Optional random 256-bit keyfile
- Argon2id benchmark/tuning screen
- Fresh random nonce on every save
- Encrypted backups and restore flow
- Vault integrity and Linux permission checks
- Sensitive-buffer zeroization where practical
- Automatic clipboard clearing
- Password generator and health checks
- Search, categories, tags and favourites
- Discord-specific recovery fields with manual-only sensitive-secret storage
- Opt-in email breach scanner with provider tree and JSON views

## Install on Arch Linux / Hyprland

```bash
sudo pacman -S --needed rust cargo base-devel wl-clipboard unzip
```

Extract the release:

```bash
mkdir -p ~/Projects/Ciphera
unzip ~/Downloads/CIphera-GitHub-Beta.zip -d ~/Projects/Ciphera
cd ~/Projects/Ciphera/CIphera-GitHub-Beta
```

Build:

```bash
cargo build --release
```

Run:

```bash
./target/release/ciphera
```

Install system-wide:

```bash
chmod +x install.sh
./install.sh
```

Then launch with:

```bash
ciphera
```

`cargo build` will generate `Cargo.lock`. For an application repository, commit that lockfile before tagging a release.

## Storage

```text
Vault:       ~/.local/share/ciphera/vault.ciphera
Backups:     ~/.local/share/ciphera/backups/
Keyfile:     ~/.config/ciphera/ciphera.key
```

The source-code directory is separate from the vault. Removing a cloned CIphera repository does not remove the vault.

## Security model

The encrypted vault contains the saved credential records. CIphera derives a 256-bit key with Argon2id and uses XChaCha20-Poly1305 authenticated encryption for the vault.

Optional keyfile mode combines a separate random secret with the master password before Argon2id derivation. For meaningful protection against theft of the entire home directory, keep the keyfile on separate removable storage instead of alongside the vault.

CIphera cannot protect secrets from an already-compromised machine while the vault is unlocked. Malware, root access, keyloggers, process-memory inspection and clipboard monitoring remain outside the protection provided by encryption at rest.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/SECURITY_DESIGN.md`](docs/SECURITY_DESIGN.md).

## Breach scanner

The scanner is opt-in. CIphera displays the email selected from the vault and asks before sending it to enabled providers.

CIphera does **not** send passwords, TOTP secrets, recovery codes, Discord session secrets, notes or the vault file.

Supported provider modes:

- **XposedOrNot** — public breach analytics API.
- **LeakCheck Public API** — public source/exposure-category lookup. Powered by LeakCheck.
- **Have I Been Pwned** — optional; direct account lookup requires the user's own `HIBP_API_KEY`.
- **Mozilla Monitor** — informational/manual provider entry; CIphera does not scrape Mozilla Monitor.

Optional HIBP setup:

```bash
export HIBP_API_KEY='YOUR_KEY'
ciphera
```

Provider APIs and rate limits can change independently of CIphera. Provider errors are shown rather than silently treated as a clean result.

See [`docs/BREACH_SCANNER.md`](docs/BREACH_SCANNER.md).

## Keyfile mode

Enable from:

```text
Security
└── Enable / rotate keyfile
```

For removable storage:

```bash
export CIPHERA_KEYFILE='/run/media/$USER/YOUR_USB/ciphera.key'
ciphera
```

Back up the keyfile securely. A keyfile-protected vault is intentionally unrecoverable if all copies of the required keyfile are lost.

## Development

For the first local preparation run:

```bash
./setup-arch.sh
```

That formats the source, checks it, runs tests, creates `Cargo.lock` and builds the release binary.

Before later commits:

```bash
cargo fmt --all -- --check
cargo check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

The GitHub Actions workflow runs the non-mutating checks on pushes and pull requests.

## Project status

CIphera is currently a **beta** security project. Before relying on it for critical production secrets, the project needs broader testing, fuzzing, dependency review and an independent security audit.

Please report security issues according to [`SECURITY.md`](SECURITY.md), not through a public issue.

## License

MIT. See [`LICENSE`](LICENSE).
