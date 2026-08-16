# Security Design

## Vault encryption

CIphera serializes the vault to JSON in memory, derives a 256-bit key using Argon2id and encrypts the serialized vault with XChaCha20-Poly1305.

A new random 192-bit XChaCha nonce is created for every save.

The on-disk envelope contains metadata required to derive/decrypt the vault, including:

- format version
- Argon2id parameters
- keyfile-required flag
- auto-lock preference
- salt
- nonce
- ciphertext

The master password is not stored in the vault envelope.

## Argon2id

New v1.3 vaults default to:

```text
Memory:      128 MiB
Iterations:  4
Lanes:       1
Output:      256 bits
```

The Security menu can benchmark a baseline derivation and recommend a stronger profile depending on the machine.

## Keyfile

Keyfile mode generates 32 random bytes using the operating system CSPRNG. The password and keyfile bytes are combined as KDF input.

Keyfile rotation preserves the previous keyfile before replacing it so an existing encrypted safety backup is not immediately stranded.

## File permissions

CIphera attempts to enforce:

```text
Vault/backups/keyfiles: 0600
CIphera data/config dirs: 0700
```

These permissions do not protect against root.

## Memory

Derived encryption keys, decrypted JSON buffers and temporary keyfile buffers are zeroized where practical. Rust and operating-system behavior mean CIphera does not claim perfect erasure of every transient copy.

## Backups

Backups copy the encrypted vault envelope; plaintext exports are not part of this build. Restore creates a safety backup first.

## Cryptographic claims

CIphera does not claim to be unbreakable, impossible to crack or independently audited.
