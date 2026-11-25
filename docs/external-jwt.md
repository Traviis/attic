# External identity JWTs (optional)

Attic can accept a short-lived identity JWT issued outside Attic, alongside its
existing static HS256/RS256 tokens. Existing `attic login NAME URL TOKEN` works
with either token. There is no browser/device login, token exchange, automatic
Vault invocation, session, refresh token, or introspection endpoint.

## Server trust and permission contract

Keep the existing `[jwt.signing]` configuration. Add one trusted issuer:

```toml
[jwt.external]
issuer = "https://vault.example/v1/identity/oidc"
audience = "attic"
algorithms = ["RS256"]

[[jwt.external.mappings]]
claim = "groups"
value = "nix-builders"
[jwt.external.mappings.caches."team-*"]
r = 1
w = 1

[[jwt.external.mappings]]
claim = "roles"
value = "cache-admin"
[jwt.external.mappings.caches."team-*"]
r = 1
w = 1
cc = 1
cr = 1
cq = 1
```

Only RS256 is currently supported; the explicit allowlist must be `["RS256"]`.
Tokens require a matching `iss`, an `aud` containing the configured nonempty
Attic audience, `exp`, a nonempty `sub`, and a `kid`. Expiration, `nbf` when
present, and future `iat` are checked without clock-drift allowance: synchronize
issuer/server clocks. When external auth is configured, incoming tokens must be at most 16 KiB. Unsupported critical JWT
headers are rejected. A token's `jku`, `jwk`, `x5u`, and similar URLs never supply
keys or trigger requests.

Discovery is fetched from `ISSUER/.well-known/openid-configuration`. Its issuer
must match exactly, and its `jwks_uri` must have the same origin as the configured
issuer. Redirects are disabled for both requests. Only HTTPS is accepted except
HTTP on literal loopback IPs for isolated testing. Userinfo, query strings, and
fragments are forbidden in trust URLs. Install a valid TLS certificate for real
issuers; there is no insecure-TLS toggle. Signing RSA keys must be 2048–8192 bits,
have unique nonempty kids and compatible `alg`, `use`, and `key_ops` if present.
An invalid key set is not installed. Non-RSA keys are not used.

Keys are cached in each server process and refreshed at startup and every five
minutes. An unknown kid can trigger a refresh, globally limited to one attempt
per ten seconds, with concurrent callers coalesced. Known-kid invalid signatures
do not trigger refresh. Requests have a five-second timeout and 1 MiB response
limit. On outage, cached keys remain usable for at most ten minutes after the
last successful refresh, then external authentication fails closed. Startup
failure leaves external auth unavailable but does not disable static tokens.
Keep old keys published for outstanding token lifetimes; unknown-key retries
immediately after another refresh may need to wait ten seconds. Revocation via
key removal is bounded by this cache, not immediate; use short-lived tokens.

Mappings match **exact values in top-level arrays consisting entirely of
strings** (groups or roles). Missing, scalar, or mixed-type claims grant nothing.
Unmapped identities have no private-cache privileges. The external
`https://jwt.attic.rs/v1` claim is discarded: external tokens cannot self-assign
Attic permissions. Configure all seven existing permission bits deliberately:
`r`, `w`, `d`, `cc`, `cr`, `cq`, `cd`. Grants for the same cache pattern are ORed;
existing Attic lookup semantics remain: an exact cache entry wins, otherwise
the first matching wildcard (configuration order) wins, **not** a union of all
matching patterns. Public cache access still works anonymously as before.

Unverified `iss` selects a verifier only. Tokens claiming the configured external
issuer must pass that verifier and cannot fall back to static Attic claims.
Other tokens go through the unchanged static verifier and its issuer/audience
bindings. **Do not issue static tokens with the external issuer**; they would
select the external verifier. Do not share signing secrets across trust domains.
Rejected credentials remain unauthenticated, following existing public/private
cache and discovery behavior.

## Issuer-aware attribution

Static token identity remains its original `sub`. External effective identity is
the compact JSON string `[issuer,subject]`, for example:

```text
["https://vault.example/v1/identity/oidc","entity-id"]
```

This same principal is used for `created_by`, signature metadata identity
matching, policy-hook `token.sub`, and audit `token.principal`. If signature
identity enforcement is enabled, registered identity metadata must contain this
exact principal, not the raw external subject. Audit `token.iss` and `token.sub`
retain the separate verified issuer and raw subject; `token.jti` is retained.
Opaque claims expose verified `iss`/`sub` and locally mapped Attic permissions,
not issuer-provided Attic grants. Clients must continue treating them as opaque.
No database schema change is needed.

## External issuance and Vault Agent

Provision issuer policy separately from Attic. For Vault identity OIDC, create an
RS256 signing key, restrict its allowed client IDs, and create an identity OIDC
role with client ID `attic`, short TTL, and a template that supplies trusted group
or role arrays. Entity/group membership and template edits are security-sensitive:
only issuer administrators should control them. Issue the JWT using an
entity-associated Vault login (e.g. `vault read -field=token
identity/oidc/token/attic`). A Vault service token is **not** an Attic JWT. The
configured issuer must match the actual token issuer and discovered metadata.
The isolated regression test in `integration-tests/external-jwt/test.py` shows a
complete disposable Vault setup; do not copy its dev-root credentials to a real
installation.

For a one-time supplied token:

```sh
attic login company https://cache.example "$JWT"
```

For agent-managed rotation:

```sh
attic login company https://cache.example --token-file /run/user/1000/attic.jwt
```

The sources are mutually exclusive. Repeating login with a different explicit
source switches it; omitting both keeps an existing source. The existing client
configuration `token-file = "/path/to/jwt"` is also supported. File sources are
reread when constructing **each outgoing Attic HTTP request**, including
long-running watch/push processes. No file contents are persisted by login. A
missing/unreadable, empty, oversized (>16 KiB), non-ASCII, or whitespace-containing
file fails the request, without anonymous or old-token fallback. One conventional
trailing LF or CRLF is accepted. There is no command source.

Configure Vault Agent/template or another external credential writer to render
the identity JWT, not the Vault login token. Give the file mode `0600`, restrict
parent directories, and atomically rename a completed replacement on the same
filesystem. Do not truncate the live file while readers run; transient incomplete
content deliberately fails closed. The writer is responsible for refreshing
before expiration; Attic does not automatically retry a request rejected during
credential expiry/rotation. Inline login exposes a token to shell history/process
arguments; prefer the file source for unattended use.

### Nix private-cache limitation

`attic use` currently copies the token's **current value** into Nix's netrc
(`~/.config/nix/netrc`, mode `0600`) and configures `netrc-file`. Nix does not read
Attic's `token-file` setting, and later Vault Agent replacements do not update
that netrc snapshot. Re-run `attic use` after rotation, or arrange an independently
managed Nix-compatible netrc with appropriate daemon/trusted-user access. This
PR does not add automatic Nix credential refresh. Public pulls need no identity
JWT. Attic file refresh only covers requests sent by the Attic client.

## Qualification

`nix build -L .#checks.x86_64-linux.external-jwt` runs real isolated Vault and
Attic processes inside the Nix build sandbox, with temporary state, literal
loopback endpoints, and no inherited Vault configuration. It covers mapped and
unmapped permissions, audience/issuer/expiry rejection, Vault key rotation,
retained keys, static token coexistence, issuer-qualified upload attribution, and
inline/file login source switching. This check is in
the routine Linux CI set. Rust tests additionally cover claim/key constraints,
cache limits, mapping precedence, and per-request atomic file replacement.

`nix build -L --no-link .#checks.x86_64-linux.external-jwt-vm` boots a NixOS
VM and runs the same real Vault/Attic qualification inside the guest. This
requires KVM and verifies guest boot plus the packaged binaries and their runtime
dependencies in NixOS. Both services use guest-local loopback; this does not test
cross-host TLS or a deployed Vault instance. The VM check runs in routine Linux
CI; `stable-external-jwt-vm` is included in full qualification.

The VM also pushes two distinct 4 MiB store paths with the real `attic push`
command, deletes only those guest-created paths, and restores each exclusively
from the private cache with Nix signature verification enabled. It verifies NAR
hashes, payload bytes and symlinks. The second cycle atomically replaces the JWT
and dedicated netrc with credentials issued after Vault signing-key rotation;
login is not repeated. Unmapped credentials must fail private substitution.
Credential files are written by the test, not by Vault Agent: this qualifies
consumer behavior across replacement, not Agent template scheduling or renewal.
