# Upload signature verification configuration

Upload verification is disabled without configuration. These settings describe the
server policy and registry; upload enforcement is a separate implementation step.
They do not change the cache key trusted by clients or the signatures served on
narinfo responses.

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
configuration API change is needed. Signature enforcement consumes this policy;
configuring the switch alone does not implement that enforcement.

Startup logs report the server-wide switch, static key count, and names, without
key material.
