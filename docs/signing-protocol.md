# Upload signing

Client signing changes upload metadata only, never the local Nix store. Existing
signatures are preserved. Signing runs after missing-path computation, before any
paths in that plan are queued for upload.

```toml
[signing]
key-file = "/run/keys/nix-signing-key"
command = ["/usr/local/bin/site-signer", "--profile", "person"]
batch-size = 200
timeout = "60s"
public-keys = ["person:BASE64_PUBLIC_KEY"]
```

All settings are optional. Without configuration, signing is disabled. Key files
use Nix's `name:base64(seed || public-key)` Ed25519 secret format. Malformed files
fail the push; group/world-readable files produce a warning. `attic push
--signing-key-file PATH` overrides the configured file; `--no-sign` disables both
signers for that push. These flags cannot be combined.

The key-file signer runs first and skips paths already bearing its key name. The
command signer then adds its own signature, preserving all existing signatures.
Commands execute directly as argv, without a shell. Input travels only on stdin;
stdout contains one JSON response. One invocation handles at most `batch-size`
paths, default 200; timeout defaults to 60 seconds per invocation.

## Command input

```json
{"version":1,"paths":[{"storePath":"/nix/store/HASH-name","narHash":"sha256:NIX_BASE32","narSize":123,"references":["/nix/store/HASH-reference"],"fingerprint":"1;/nix/store/HASH-name;sha256:NIX_BASE32;123;/nix/store/HASH-reference"}]}
```

The fingerprint is the exact UTF-8 message to sign, without a trailing newline:

```text
1;<storePath>;<narHash>;<narSize>;<references>
```

`storePath` is the full path, `narHash` is `sha256:` plus Nix base32, `narSize` is
decimal, and references are full paths sorted lexicographically and comma-joined.
An empty reference list leaves the fingerprint ending in a semicolon. Sign these
bytes with Ed25519, not a digest or a JSON encoding of the string.

## Command response

```json
{"signatures":["person:BASE64_ED25519_SIGNATURE"]}
```

Exactly one signature per input path, positionally matched. Configured
`public-keys` verify each returned signature locally against its fingerprint and
matching Nix key name. With no public keys, a notice states that verification
relies on the server. Invalid JSON, mismatched response length, failed local
verification, nonzero exit, output over 1 MiB, or timeout fails the plan before
upload queueing. Stderr is drained with at most 64 KiB retained and escaped for
terminal output. Signer programs must never emit credentials or secret material.
