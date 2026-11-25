# Native sandbox test: real ephemeral Vault and Attic, loopback only. No VM or
# credentials needed. The Vault package is build-time test infrastructure only.
{ pkgs }:
pkgs.runCommand "attic-external-jwt" {
  nativeBuildInputs = [ pkgs.attic pkgs.python3 pkgs.vault ];
} ''
  python3 ${./test.py}
  touch $out
''
