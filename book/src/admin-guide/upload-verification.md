# Upload signature verification configuration

Upload verification is disabled without configuration. When enabled, each upload
requires the configured minimum of distinct, valid registered signing keys before
NAR deduplication. There is no content-addressed-path exemption. These settings do
not change the cache key trusted by clients or signatures served on narinfo.

```toml
[upload-verification]
enabled = false
min-signatures = 1
identity-match = "off" # off | warn | enforce
identity-field = "identity"
trusted-public-keys = ["alice-1:BASE64_PUBLIC_KEY"]

[[upload-verification.trusted-keys]]
public-key = "alice-1:BASE64_PUBLIC_KEY"
valid-from = "2026-11-01T00:00:00Z"
valid-until = "2027-11-01T00:00:00Z"
revoked = false
metadata = { identity = "alice", kind = "host", generation = 1, managed = true }

[upload-verification.caches.private]
enabled = true
```

Replace the illustrative public key with a valid Nix Ed25519 public key. The key
name is derived from its prefix; no separate name is accepted. The simple list
uses the same key format as Nix's `trusted-public-keys` setting.

A simple and a detailed entry for the same name and public key combine; the
detailed entry supplies validity and metadata. Multiple simple entries for the
same key are harmless. Conflicting public keys with one name, multiple detailed
entries for a name, malformed keys, invalid RFC3339 timestamps, reversed validity
windows, and a minimum below one are startup errors.

Metadata is a flat map of strings, numbers, and booleans. Attic interprets only the
field selected by `identity-field` for identity matching; other metadata belongs
to external policy. Identity matching defaults to `off`.

Cache switches are server-owned configuration, keyed by exact cache name under
`upload-verification.caches`. They override only `enabled`, in either direction;
unspecified caches inherit the server-wide switch. No database schema or cache
configuration API change is needed. Enabled verification also requires body
hash/size validation on deduplicated uploads, even when proof-of-possession is
disabled. Same-content uploads preserve the original uploader and accumulate
signatures when verification or overwrite protection is enabled.

Startup logs report the server-wide switch, static key count, and names, without
key material.

## Audit and overwrite protection

Top-level server settings:

```toml
protect-path-overwrites = true
upload-audit = true
```

Overwrite protection defaults to false. When enabled, a different NAR hash for an
existing cache/store-path hash returns 409 without replacing the original object.
Same-content requests keep original attribution and accumulate signatures.

Audit defaults to enabled when OTEL log export is configured, independently of
verification. Set `upload-audit` explicitly to override this. The named logger
`attic.audit` exports typed decision attributes, with supplied signatures encoded
as JSON. It includes registered public keys and metadata, never secret keys or
full bearer tokens. The client address is the direct transport peer, not an
untrusted forwarded header. Export failures fall back to operational WARN logs.

Release note: overwrite protection and signature verification are explicit opt-in
features; existing no-config upload behavior is retained.
