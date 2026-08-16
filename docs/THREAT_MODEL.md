# Threat Model

## CIphera aims to protect against

- Theft or copying of `vault.ciphera` while CIphera is locked.
- Casual inspection of vault/backups by another unprivileged local user.
- Modification/corruption of encrypted vault ciphertext.
- Offline guessing made more expensive through Argon2id.
- Theft of the vault without the optional external keyfile.
- Accidental long-lived clipboard exposure through timed clearing.

## CIphera does not claim to protect against

- Root or kernel-level compromise.
- Malware running as the same user while the vault is unlocked.
- Keyloggers capturing the master password.
- Process-memory inspection of live decrypted data.
- Screen capture while a secret is revealed.
- Clipboard interception before the clipboard is cleared.
- Physical attacks on an unlocked running machine.
- Weak or reused master passwords.
- Loss of both the vault and all backups.
- Loss of every copy of a required keyfile.

## Keyfile assumption

Keyfile mode materially improves stolen-vault resistance only when the attacker does not obtain the keyfile as well. Keeping the keyfile in the same home directory as the vault protects against some single-file theft scenarios, but removable/off-device storage provides the stronger model.

## Breach-scanner privacy boundary

The scanner requires user confirmation before sending a selected email to network providers. The email itself becomes visible to those providers. Vault passwords and other stored secrets are not intentionally transmitted.
