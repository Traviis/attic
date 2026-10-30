# Attic

**Attic** is a self-hostable Nix Binary Cache server backed by an S3-compatible storage provider.
It has support for global deduplication and garbage collection.

Attic is an early prototype.

```
⚙️ Pushing 5 paths to "demo" on "local" (566 already cached, 2001 in upstream)...
✅ gnvi1x7r8kl3clzx0d266wi82fgyzidv-steam-run-fhs (29.69 MiB/s)
✅ rw7bx7ak2p02ljm3z4hhpkjlr8rzg6xz-steam-fhs (30.56 MiB/s)
✅ y92f9y7qhkpcvrqhzvf6k40j6iaxddq8-0p36ammvgyr55q9w75845kw4fw1c65ln-source (19.96 MiB/s)
🕒 vscode-1.74.2        ███████████████████████████████████████  345.66 MiB (41.32 MiB/s)
🕓 zoom-5.12.9.367      ███████████████████████████              329.36 MiB (39.47 MiB/s)
```

## Try it out (15 minutes)

Let's [spin up Attic](https://docs.attic.rs/tutorial.html) in just 15 minutes.
And yes, it works on macOS too!

## Goals

- **Multi-Tenancy**: Create a private cache for yourself, and one for friends and co-workers. Tenants are mutually untrusting and cannot pollute the views of other caches.
- **Global Deduplication**: Individual caches (tenants) are simply restricted views of the content-addressed NAR Store and Chunk Store. When paths are uploaded, a mapping is created to grant the local cache access to the global NAR.
- **Managed Signing**: Signing is done on-the-fly by the server when store paths are fetched. The user pushing store paths does not have access to the signing key.
- **Scalabilty**: Attic can be easily replicated. It's designed to be deployed to serverless platforms like fly.io but also works nicely in a single-machine setup.
- **Garbage Collection**: Unused store paths can be garbage-collected in an LRU manner.

## OCI images and releases

Build an OCI image archive with Nix:

```sh
nix build .#attic-server-image
skopeo copy oci-archive:result docker://registry.example.com/attic:version
```

`attic-server-image` targets the current Linux platform. On x86_64 Linux,
`attic-server-image-aarch64` cross-builds the arm64 image. Both archives contain
`atticd` and `atticadm`, with `/bin/atticd` as the entrypoint. Mount a server
configuration and pass `-f /path/to/server.toml` to select it explicitly.

Releases use CalVer `YYYY.M.PATCH` and two manually dispatched Actions workflows:

1. **Prepare release** accepts an optional version. By default it starts the
   current UTC month at patch zero, or increments the patch within that month.
   It updates all four Rust packages, their lockfile entries, and the Nix
   package version, then opens a release PR and dispatches Build for its branch.
2. Review and merge that PR into `main`.
3. **Publish release**, run on `main` with the prepared version, runs the Build
   qualification jobs, checks version agreement and tag availability, and creates
   a draft GitHub Release. It publishes an amd64/arm64 OCI index to
   `ghcr.io/traviis/attic`, tagged with the full commit SHA and version, then
   publishes the GitHub Release. Image failure leaves the release as a draft.

No scheduled releases or moving `latest` tags. Pin deployments to a registry
digest. Repository Actions settings must permit workflows to create pull
requests; the repository token needs package publication permission.

The `docker://` Skopeo transport names the registry protocol; it does not require
a Docker daemon or convert the OCI manifests to Docker format.

## Licensing

Attic is available under the **Apache License, Version 2.0**.
See `LICENSE` for details.

By contributing to the project, you agree to license your work under the aforementioned license.
