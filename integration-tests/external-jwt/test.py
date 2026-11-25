#!/usr/bin/env python3
"""Real disposable Vault + Attic; no inherited Vault configuration or credentials.

Run with atticd, atticadm, attic and vault on PATH. All state lives in a temporary
folder; both services bind literal loopback on dynamically selected ports.
"""

import base64
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url, token=None, data=None, method=None):
    assert urlsplit(url).scheme == "http" and urlsplit(url).hostname == "127.0.0.1"
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data).encode()
    req = urllib.request.Request(  # noqa: S310 - URLs are constructed literal loopback test endpoints
        url, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310 - loopback test endpoint
            body = response.read()
            return response.status, body
    except urllib.error.HTTPError as error:
        return error.code, None


def ready(url):
    for _ in range(100):
        try:
            request(url)
            return
        except (OSError, TimeoutError):
            time.sleep(0.1)
    raise AssertionError("isolated service failed to start")


def run():
    with tempfile.TemporaryDirectory(prefix="attic-vault-jwt-") as directory:
        root = Path(directory)
        vault_url = f"http://127.0.0.1:{port()}"
        attic_url = f"http://127.0.0.1:{port()}"
        # Deliberately not using os.environ: neither the developer's live Vault
        # endpoint/token nor Vault CLI token-helper configuration can be used.
        env = {
            "PATH": os.environ["PATH"],
            "HOME": directory,
            "XDG_CONFIG_HOME": directory,
        }
        # Only forward the public CA bundle, never Vault credentials/config.
        if "SSL_CERT_FILE" in os.environ:
            env["SSL_CERT_FILE"] = os.environ["SSL_CERT_FILE"]
        processes = []
        with (
            (root / "vault.log").open("w+") as vault_log,
            (root / "attic.log").open("w+") as attic_log,
        ):
            try:
                processes.append(
                    subprocess.Popen(
                        [
                            "vault",
                            "server",
                            "-dev",
                            "-dev-root-token-id=isolated-test-only",
                            "-dev-listen-address=" + vault_url.removeprefix("http://"),
                        ],
                        env=env,
                        stdout=vault_log,
                        stderr=subprocess.STDOUT,
                    )
                )
                ready(vault_url + "/v1/sys/health")

                def vault(path, data=None):
                    # X-Vault-Token, unlike Attic's bearer authorization.
                    req = urllib.request.Request(  # noqa: S310 - URLs are constructed literal loopback test endpoints
                        vault_url + "/v1/" + path,
                        data=None if data is None else json.dumps(data).encode(),
                        headers={
                            "X-Vault-Token": "isolated-test-only",
                            "Content-Type": "application/json",
                        },
                    )
                    with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310 - loopback test endpoint
                        body = response.read()
                        return json.loads(body) if body else {}

                vault("identity/oidc/config", {"issuer": vault_url})
                vault("identity/entity/name/alice", {})
                entity_id = vault("identity/entity/name/alice")["data"]["id"]
                vault(
                    "identity/oidc/key/attic",
                    {
                        "algorithm": "RS256",
                        "allowed_client_ids": ["attic", "other"],
                        "rotation_period": "1h",
                        "verification_ttl": "2h",
                    },
                )

                def role(name, audience="attic", ttl="1h", group="builders"):
                    template = base64.b64encode(
                        json.dumps({"groups": [group]}).encode()
                    ).decode()
                    vault(
                        "identity/oidc/role/" + name,
                        {
                            "key": "attic",
                            "client_id": audience,
                            "ttl": ttl,
                            "template": template,
                        },
                    )

                # Use userpass to obtain a genuine entity-associated login.
                vault("sys/auth/userpass", {"type": "userpass"})
                accessor = vault("sys/auth")["userpass/"]["accessor"]
                vault(
                    "identity/entity-alias",
                    {
                        "name": "alice",
                        "canonical_id": entity_id,
                        "mount_accessor": accessor,
                    },
                )
                vault(
                    "sys/policies/acl/issuer",
                    {
                        "policy": 'path "identity/oidc/token/*" { capabilities = ["read"] }'
                    },
                )
                vault(
                    "auth/userpass/users/alice",
                    {"password": "isolated-password", "policies": ["issuer"]},
                )
                user_token = vault(
                    "auth/userpass/login/alice", {"password": "isolated-password"}
                )["auth"]["client_token"]

                def issue(name):
                    req = urllib.request.Request(  # noqa: S310 - URLs are constructed literal loopback test endpoints
                        vault_url + "/v1/identity/oidc/token/" + name,
                        headers={"X-Vault-Token": user_token},
                    )
                    with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310 - loopback test endpoint
                        return json.load(response)["data"]["token"]

                role("builder")
                role("wrong-audience", audience="other")
                role("unmapped", group="strangers")
                role("expired", ttl="1s")
                issuer = vault_url + "/v1/identity/oidc"
                config = root / "server.toml"
                config.write_text(f'''
listen = "{attic_url.removeprefix("http://")}"
[database]
url = "sqlite://{root}/server.db?mode=rwc"
[storage]
type = "local"
path = "{root}/storage"
[chunking]
nar-size-threshold = 0
min-size = 16384
avg-size = 65536
max-size = 262144
[jwt.signing]
token-hs256-secret-base64 = "aXNvbGF0ZWQgdGVzdCBzZWNyZXQ="
[jwt.external]
issuer = "{issuer}"
audience = "attic"
algorithms = ["RS256"]
[[jwt.external.mappings]]
claim = "groups"
value = "builders"
[jwt.external.mappings.caches.test]
r = 1
w = 1
cc = 1
''')
                static = subprocess.check_output(
                    [
                        "atticadm",
                        "-f",
                        str(config),
                        "make-token",
                        "--sub",
                        "static",
                        "--validity",
                        "1h",
                        "--pull",
                        "*",
                        "--create-cache",
                        "*",
                    ],
                    env=env,
                    text=True,
                ).strip()
                processes.append(
                    subprocess.Popen(
                        ["atticd", "-f", str(config)],
                        env=env,
                        stdout=attic_log,
                        stderr=subprocess.STDOUT,
                    )
                )
                ready(attic_url + "/")
                cache_url = attic_url + "/_api/v1/cache-config/test"
                create = {
                    "keypair": "Generate",
                    "is_public": False,
                    "store_dir": "/nix/store",
                    "priority": 40,
                    "upstream_cache_key_names": [],
                }
                assert request(cache_url, static, create, "POST")[0] == 200
                good = issue("builder")
                assert request(cache_url, good)[0] == 200
                assert (
                    request(
                        attic_url + "/_api/v1/get-missing-paths",
                        good,
                        {"cache": "test", "store_path_hashes": []},
                        "POST",
                    )[0]
                    == 200
                )
                assert request(cache_url, static)[0] == 200
                assert request(cache_url, issue("wrong-audience"))[0] == 401
                assert request(cache_url, issue("unmapped"))[0] == 401
                # Pull/push grants do not imply cache destruction.
                assert request(cache_url, good, method="DELETE")[0] == 403
                assert (
                    request(
                        attic_url + "/_api/v1/cache-config/other", good, create, "POST"
                    )[0]
                    == 401
                )
                # Attribute a real upload to the same issuer-qualified principal
                # used by signature identity checks and hooks.
                nar = b"nar"
                info = {
                    "cache": "test",
                    "store_path_hash": "0" * 32,
                    "store_path": "/nix/store/" + "0" * 32 + "-example",
                    "references": [],
                    "sigs": [],
                    "nar_hash": "sha256:" + hashlib.sha256(nar).hexdigest(),
                    "nar_size": len(nar),
                }
                upload = urllib.request.Request(  # noqa: S310 - loopback test endpoint
                    attic_url + "/_api/v1/upload-path",
                    data=nar,
                    method="PUT",
                    headers={
                        "Authorization": "Bearer " + good,
                        "X-Attic-Nar-Info": json.dumps(info),
                    },
                )
                with urllib.request.urlopen(upload, timeout=10) as response:  # noqa: S310 - loopback test endpoint
                    assert response.status == 200
                with sqlite3.connect(root / "server.db") as database:
                    principal = database.execute(
                        "SELECT created_by FROM object"
                    ).fetchone()[0]
                    assert json.loads(principal) == [issuer, entity_id]
                expired = issue("expired")
                time.sleep(2)
                assert request(cache_url, expired)[0] == 401
                vault(
                    "identity/oidc/config", {"issuer": "https://wrong-issuer.example"}
                )
                assert request(cache_url, issue("builder"))[0] == 401
                vault("identity/oidc/config", {"issuer": vault_url})
                # Wait out the bounded unknown-kid refresh interval, rotate the
                # real Vault key, then accept both new and retained old keys.
                time.sleep(10)
                vault("identity/oidc/key/attic/rotate", {})
                rotated = issue("builder")
                assert rotated.split(".")[0] != good.split(".")[0]
                assert request(cache_url, rotated)[0] == 200
                assert request(cache_url, good)[0] == 200
                # Existing login supports supplied external JWT and file source.
                assert (
                    subprocess.run(
                        ["attic", "login", "isolated", attic_url, good], env=env
                    ).returncode
                    == 0
                )
                subprocess.run(
                    ["attic", "cache", "info", "isolated:test"], env=env, check=True
                )
                token_file = root / "agent.jwt"
                token_file.write_text(rotated + "\n")
                token_file.chmod(0o600)
                subprocess.run(
                    [
                        "attic",
                        "login",
                        "isolated",
                        attic_url,
                        "--token-file",
                        str(token_file),
                    ],
                    env=env,
                    check=True,
                )
                subprocess.run(
                    ["attic", "cache", "info", "isolated:test"], env=env, check=True
                )
                client_config = root / "attic/config.toml"
                assert "token-file" in client_config.read_text()
                assert rotated not in client_config.read_text()
                token_file.unlink()
                missing_token = subprocess.run(
                    ["attic", "cache", "info", "isolated:test"],
                    env=env,
                    capture_output=True,
                    text=True,
                )
                assert missing_token.returncode != 0
                assert "Failed to read token file" in missing_token.stderr
                assert str(token_file) in missing_token.stderr
                assert not missing_token.stdout
                assert (
                    good not in missing_token.stderr
                    and rotated not in missing_token.stderr
                )
                # Explicitly switch back to the original inline source.
                assert (
                    subprocess.run(
                        ["attic", "login", "isolated", attic_url, good], env=env
                    ).returncode
                    == 0
                )
                subprocess.run(
                    ["attic", "cache", "info", "isolated:test"], env=env, check=True
                )
                print(
                    "PASS: real Vault permissions, issuer/audience/expiry, key rotation, static coexistence, inline/file login"
                )
            except Exception:
                # Vault dev startup logs contain test credentials: never print them.
                attic_log.flush()
                attic_log.seek(0)
                print(attic_log.read())
                raise
            finally:
                for process in reversed(processes):
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    run()
