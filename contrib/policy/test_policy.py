import json
import subprocess
import sys
import unittest
from pathlib import Path


class PolicyTests(unittest.TestCase):
    def evaluate(self, subject, signatures):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("example-policy"))],
            input=json.dumps(
                {"version": 1, "token": {"sub": subject}, "signatures": signatures}
            ),
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)["allow"]

    def signature(self, kind, identity, status="valid"):
        return {"status": status, "metadata": {"kind": kind, "identity": identity}}

    def test_person_requires_both_and_matching_vault(self):
        host = self.signature("host", "builder")
        vault = self.signature("vault", "alice")
        self.assertTrue(self.evaluate("alice", [host, vault]))
        self.assertFalse(self.evaluate("alice", [host]))
        self.assertFalse(self.evaluate("alice", [vault]))
        self.assertFalse(self.evaluate("bob", [host, vault]))
        self.assertFalse(
            self.evaluate("alice", [host, self.signature("vault", "alice", "revoked")])
        )

    def test_service_requires_matching_service_key(self):
        self.assertTrue(self.evaluate("svc/ci", [self.signature("service", "svc/ci")]))
        self.assertFalse(
            self.evaluate("svc/ci", [self.signature("service", "svc/other")])
        )
        self.assertFalse(
            self.evaluate(
                "svc/ci",
                [self.signature("vault", "svc/ci"), self.signature("host", "ci")],
            )
        )


if __name__ == "__main__":
    unittest.main()
