# End-to-End Tests

This directory contains some end-to-end tests for Attic.

## Store implementation compatibility

Run the Linux x86_64 qualification with KVM available:

```console
nix build .#checks.x86_64-linux.lix .#checks.x86_64-linux.basic-sqlite-local --no-link -L
```

The `lix` check uses the Lix package from the locked nixpkgs input as the
client machine's CLI and daemon. Attic remains the ordinary Nix-linked client
package. The test verifies daemon identity and stops the daemon to establish
that uploads cannot bypass it through direct local-store access.

The existing SQLite/local-storage suite exercises cache permissions, compressed
and uncompressed uploads, substitution, and garbage collection. The Lix variant
also uploads a multi-chunk closure, deletes its local paths, restores exclusively
from Attic, and verifies NAR hashes, dependency presence, executable mode, and a
symlink. Negative narinfo caching is disabled for that restoration because the
fixture's build queries the cache before its first upload.

Both `lix` and `stable-lix` are available as flake checks. Routine CI runs
`basic-sqlite-local`, `basic-postgres-garage`, and `lix`. Manual Build dispatch
with `full` enabled, and release qualification, run nine functional VM
variants, including stable nixpkgs database/storage variants. `stable-lix` is
excluded from every CI mode to avoid redundant Lix/toolchain source builds;
it remains directly runnable as a flake check. Lix versions follow their
respective locked nixpkgs inputs.

Routine Rust tests run on Linux/default, macOS/default, and Linux/Nix 2.28.
Full qualification tests all five listed Nix versions on both platforms.
WebAssembly builds once on Linux/default in either mode. Package builds on
Linux/macOS are unchanged.

Performance checks run only when the manual Build dispatch explicitly enables
`benchmarks`; `full` alone does not enable them. Both performance checks also
remain directly runnable through their flake check attributes.

Local qualification passed with Lix 2.94.2 from the primary input and with the
Nix baseline. The stable-input check was blocked before VM execution by the
Lix package's own `FileTransfer.destructionAbortsDownload` unit test crashing
with SIGILL; its dependency tests remain enabled.

This qualifies daemon/protocol interoperability, not compilation against Lix
C++ libraries. It does not qualify macOS, ARM, content-addressed derivation
realisations, watch-store, or interrupted uploads. The Lix variant uses SQLite
and local storage; the existing Nix matrix separately covers PostgreSQL/Garage.
