import base64
import runpy
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

resolver = runpy.run_path(str(Path(__file__).with_name("vault-resolver")))
PUBLIC = base64.b64encode(bytes(32)).decode()


class ResolverTests(unittest.TestCase):
    def test_transit_versions_and_safety(self):
        data = {
            "type": "ed25519",
            "keys": {"1": {"public_key": PUBLIC}, "2": {"public_key": PUBLIC}},
        }
        entries = resolver["transit_entries"]("alice", data)
        self.assertEqual(
            [entry["publicKey"] for entry in entries],
            ["alice-vault-1:" + PUBLIC, "alice-vault-2:" + PUBLIC],
        )
        self.assertEqual(entries[0]["metadata"], {"identity": "alice", "kind": "vault"})
        for flag in ("exportable", "allow_plaintext_backup", "imported_key"):
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(
                    resolver["transit_entries"]("alice", dict(data, **{flag: True})), []
                )
            self.assertEqual(errors.getvalue(), "Skipping unsafe transit key\n")

    def test_imported_version_is_excluded(self):
        data = {
            "type": "ed25519",
            "keys": {
                "1": {"public_key": PUBLIC, "imported": True},
                "2": {"public_key": PUBLIC},
            },
        }
        errors = StringIO()
        with redirect_stderr(errors):
            entries = resolver["transit_entries"]("alice", data)
        self.assertEqual(
            [entry["publicKey"] for entry in entries], ["alice-vault-2:" + PUBLIC]
        )
        self.assertEqual(errors.getvalue(), "Skipping unsafe transit key version\n")

    def test_location_controls_metadata_and_names(self):
        host = resolver["registered_entry"](
            "alice",
            ["alice", "hosts", "laptop"],
            {
                "publicKey": "alice-laptop-1:" + PUBLIC,
                "metadata": {"kind": "vault", "identity": "bob"},
                "revoked": True,
            },
        )
        self.assertEqual(host["metadata"], {"identity": "alice", "kind": "host"})
        self.assertTrue(host["revoked"])
        service = resolver["registered_entry"](
            "ci", ["svc", "ci", "builder"], {"publicKey": "ci-builder-2:" + PUBLIC}
        )
        self.assertEqual(service["metadata"], {"identity": "svc/ci", "kind": "service"})
        with self.assertRaises(ValueError):
            resolver["registered_entry"](
                "alice",
                ["alice", "hosts", "laptop"],
                {"publicKey": "bob-laptop-1:" + PUBLIC},
            )


if __name__ == "__main__":
    unittest.main()
