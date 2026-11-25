# Native sandbox test: real ephemeral Vault and Attic, loopback only. No VM or
# credentials needed. Vault's BSL license is allowed only for this test tool.
{ pkgs }:
let
  vault = (import pkgs.path {
    inherit (pkgs.stdenv.hostPlatform) system;
    config.allowUnfreePredicate = package: pkgs.lib.getName package == "vault";
  }).vault;
in
pkgs.runCommand "attic-external-jwt" {
  nativeBuildInputs = [ pkgs.attic pkgs.python3 vault ];
  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
} ''
  python3 ${./test.py}
  touch $out
''
