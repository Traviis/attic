{ pkgs, ... }:
let
  vault = (import pkgs.path {
    inherit (pkgs.stdenv.hostPlatform) system;
    config.allowUnfreePredicate = package: pkgs.lib.getName package == "vault";
  }).vault;
in {
  name = "external-jwt-vm";

  nodes.machine = { ... }: {
    environment.systemPackages = [ pkgs.attic pkgs.python3 vault ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
  };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    with subtest("Vault-issued JWTs and rotating client credentials"):
        machine.succeed("python3 ${./test.py}")
  '';
}
