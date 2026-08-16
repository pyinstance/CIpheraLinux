# Breach Scanner

CIphera's breach scanner is an optional network feature. The rest of the vault can be used without it.

## Data sent

When the user selects an email and confirms scanning, CIphera may send that **email address** to enabled providers.

It does not intentionally send:

- passwords
- TOTP secrets
- recovery codes
- Discord session secrets
- notes
- vault ciphertext/plaintext
- keyfiles

## Providers

### XposedOrNot

CIphera uses the public breach-analytics endpoint and normalizes breach details for the tree view.

### LeakCheck Public

CIphera uses the unauthenticated Public API. The public response is intended to provide breach sources and exposed-data categories rather than leaked secret values.

Attribution: **Powered by LeakCheck**.

### Have I Been Pwned

Direct email-account searches are enabled only when `HIBP_API_KEY` is present in the environment.

### Mozilla Monitor

Shown as an informational/manual provider entry. CIphera does not scrape Mozilla Monitor.

## Result handling

Results are displayed in memory as:

- provider status
- normalized breach tree
- normalized JSON
- raw JSON response for troubleshooting

This beta build does not intentionally persist breach API responses to disk.

## Limitations

Third-party APIs, schemas, availability, terms and rate limits can change. A provider error must not be interpreted as proof that an email has never appeared in a breach.
