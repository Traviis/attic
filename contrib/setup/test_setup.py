import argparse
import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

setup = runpy.run_path(str(Path(__file__).with_name("register-host-key")))


class SetupTests(unittest.TestCase):
    def test_disposable_root_requires_explicit_store_before_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(
                root=Path(directory),
                store=None,
                identity="alice",
                host="laptop",
                generation=1,
            )
            with patch(
                "subprocess.run", side_effect=AssertionError("unexpected subprocess")
            ) as command:
                with self.assertRaisesRegex(ValueError, "explicit isolated"):
                    setup["register"](args)
                command.assert_not_called()

    def test_rejects_symlinked_installation_paths_without_touching_target(self):
        for target in (
            "etc",
            "etc/nix",
            "etc/nix/nix.conf",
            "etc/nix/alice-laptop-1.signed",
        ):
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory) / "root"
                root.mkdir()
                outside = Path(directory) / "outside"
                outside.write_text("untouched")
                link = root / target
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(outside)
                args = argparse.Namespace(
                    root=root,
                    store=Path(directory) / "store",
                    identity="alice",
                    host="laptop",
                    generation=1,
                )
                with patch(
                    "subprocess.run",
                    side_effect=AssertionError("unexpected subprocess"),
                ) as command:
                    with self.assertRaisesRegex(ValueError, "symlinks"):
                        setup["register"](args)
                    command.assert_not_called()
                self.assertEqual(outside.read_text(), "untouched")
                self.assertFalse((root / "etc/nix/alice-laptop-1.key").exists())


if __name__ == "__main__":
    unittest.main()
