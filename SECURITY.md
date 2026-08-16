# Security Policy

## Project status

CIphera is beta software and has not undergone an independent security audit.

## Reporting a vulnerability

Please do **not** open a public GitHub issue containing a vulnerability, exploit, private vault material, API keys, session credentials or other secrets.

Until a dedicated private security contact is configured for the repository, use GitHub's private vulnerability reporting feature if it is enabled for the repository.

A useful report includes:

- affected CIphera version/commit
- operating system
- minimal reproduction steps
- expected vs actual behavior
- security impact
- whether the issue requires an unlocked vault or local/root access

Do not include real passwords, tokens, recovery codes or vault files in reports.

## Supported versions

During beta, only the latest tagged release is supported with security fixes.

## Scope

Security reports are welcome for:

- vault encryption/decryption
- key derivation and keyfile behavior
- plaintext leakage to files/logs
- unsafe file permissions
- backup/restore integrity
- clipboard handling
- breach-scanner privacy behavior

Third-party breach-provider outages, database contents and provider-side vulnerabilities should be reported to the relevant provider.
