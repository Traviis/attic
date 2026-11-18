# Upload attribution with host and Vault signatures

Attic core verifies registered public keys, a minimum distinct signature count,
and optional metadata identity matching. It does not interpret `kind`. Pull trust
is unchanged: Attic signs served narinfo with its cache key.

## Small static deployment

Generate a Nix Ed25519 key outside the repository:

```sh
umask 077
nix key generate-secret --key-name alice-1 > alice-1.key
nix key convert-secret-to-public < alice-1.key
```

Register its public output in server configuration:

```toml
[upload-verification]
enabled = true
min-signatures = 1
trusted-public-keys = ["alice-1:BASE64_PUBLIC_KEY"]
```

Client configuration:

```toml
[signing]
key-file = "/run/keys/alice-1.key"
```

See [signing protocol](signing-protocol.md) and the admin guide for validity,
identity matching, audit, and overwrite protection.

## Host at build time, developer at push time

Recommended person workflow: Nix daemon `secret-key-files` signs builds with a
host key; the developer's push adds a Vault transit signature. Register personal
hosts under that developer identity; shared builders use their own identity.
The example person policy requires a matching Vault identity and any registered
host signature. A host signature proves a registered machine produced or signed
the path, not which human built it. No `post-build-hook`: hooks run as daemon
identity, block builds, and cannot attach a ready-made signature through a Nix
CLI operation. Daemon signing plus a push command avoids that coupling.

The scripts under `contrib/` are examples, not built-in Attic features. Install
reviewed copies with executable permissions or invoke them through `python3`.
Dependencies: Python3 standard library, Nix CLI, OpenSSL for `keyfile-signer`.
Use a proper TLS Vault endpoint; `VAULT_ADDR`, `VAULT_TOKEN`, and optionally
`VAULT_NAMESPACE` are read from the process environment. Never place tokens in
argv, scripts, or checked-in configuration. Do not print secret key material.

## Vault operator setup

Operators, not developers, enable transit and create keys:

```sh
vault secrets enable transit
vault write transit/keys/nix-alice type=ed25519 exportable=false allow_plaintext_backup=false
```

Do not grant developers transit key create/configure/import/export privileges.
`contrib/resolvers/vault-resolver` refuses exportable, plaintext-backup-enabled,
or imported transit keys; it emits one public entry per version named
`alice-vault-1`, `alice-vault-2`, etc. Metadata is derived from key location:

- `transit/keys/nix-alice`: identity `alice`, kind `vault`.
- KVv2 `secret/nix-keys/alice/hosts/laptop`: identity `alice`, kind `host`;
  public key name `alice-laptop-1` (positive generation).
- KVv2 `secret/nix-keys/svc/ci/builder`: identity `svc/ci`, kind `service`;
  public key name `ci-builder-1`. Service registry writes are operators-only.

KV records contain `publicKey`, optionally `validFrom`, `validUntil`, `revoked`.
Caller-supplied metadata cannot change derived identity or kind. Registry records
must live at these exact depths. Resolver needs transit list/read and KVv2
metadata list/data read permissions, never transit signing or private-key export.
A resolver error exits nonzero so Attic retains the last-known-good snapshot.

Example developer Vault ACL (adapt to your authentication identity aliases):

```hcl
path "transit/sign/nix-{{identity.entity.name}}" {
  capabilities = ["update"]
}
path "secret/data/nix-keys/{{identity.entity.name}}/hosts/*" {
  capabilities = ["create", "update"]
}
```

Do not give developers access to `secret/data/nix-keys/svc/*`. Reserve the `svc`
identity namespace for operators. A developer may register only their own host
keys; a shared builder's registration requires its owner's/operator's policy.

## Host registration

Review `contrib/setup/register-host-key` before operator execution. It generates
a key only if absent, installs root-owned mode0400 key under `/etc/nix`, appends
`extra-secret-key-files` to `nix.conf`, signs existing store paths once, and writes
the public key to the developer's own hosts KV path. Reruns reuse the key and do
not repeat initial signing. Restart `nix-daemon` through your normal host change
process. No host apply is performed by Attic.

```sh
python3 contrib/setup/register-host-key alice laptop
```

`--root /disposable/path --store /disposable/store` redirects installation files
and Nix operations for qualification. A non-host installation root requires an
explicit absolute store path. Setup rejects symlinked installation paths before
running commands. These flags do not create a chroot or change the Vault target;
qualification must also use a disposable Vault endpoint.

## Full server and client configuration

```toml
# Server
[upload-verification]
enabled = true
min-signatures = 2
identity-match = "enforce"
identity-field = "identity"

[upload-verification.resolver]
command = ["python3", "/opt/attic/contrib/resolvers/vault-resolver"]
refresh-interval = "5m"
command-timeout = "10s"
unknown-key-refresh-limit = "6/min"

[upload-verification.policy-hook]
command = ["python3", "/opt/attic/contrib/policy/example-policy"]
timeout = "2s"
```

```toml
# Developer client; daemon already supplies host signature
[signing]
command = ["python3", "/opt/attic/contrib/signers/vault-transit-signer", "alice"]
batch-size = 200
timeout = "60s"
public-keys = ["alice-vault-1:BASE64_PUBLIC_KEY"]
```

The transit signer uses one `batch_input` request per command batch, strips
`vault:vN:`, and attaches `alice-vault-N:`. Local public keys must include every
version expected during rotation. `keyfile-signer` is a protocol reference; the
built-in client key-file signer avoids an extra process.

Example policy convention: token `sub` starting `svc/` requires a valid service
signature with exactly matching identity. Person tokens require valid matching
Vault signature plus valid host signature. For service-only caches override
`enabled` and hook as appropriate and use server `min-signatures = 1` if a single
service key is intended; `min-signatures = 2` cannot be relaxed by a hook.

Vault outage fails developer pushes because transit signing fails. Resolver
last-known-good data is not a host-only fallback. The policy rejects host-only
person uploads. Pulling does not depend on Vault and remains unaffected.

## Rotation and evidence

For static/host keys rotate `alice-1` to `alice-2` (or host generation1 to2): add
the replacement, retain the previous detailed entry with `validUntil`, distribute
trust, then switch signing. Never delete registry history to hide attribution.
The host registration example updates one current KV record; operators must
retain prior detailed public entries in an archival static source with validity
metadata before replacing that record. Transit versions remain in the resolver;
retain their metadata/history and configure retirement deliberately.

Real isolated Vault1.21.4 Ed25519 transit signatures were imported through
`nix store copy-sigs` and accepted by `nix store verify --sigs-needed 1`. The
protocol signs the exact Nix fingerprint, not a digest. This establishes format
interoperability, not production Vault policy or deployment qualification.
