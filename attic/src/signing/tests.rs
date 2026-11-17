use super::*;
use crate::hash::Hash;
use std::path::Path;

#[test]
fn fingerprint_orders_references() {
    let hash = Hash::sha256_from_bytes(b"nar");
    let references = ["/nix/store/z-reference", "/nix/store/a-reference"];
    let message = fingerprint(Path::new("/nix/store/path"), &hash, 123, &references);
    assert_eq!(
        message,
        format!(
            "1;/nix/store/path;{};123;/nix/store/a-reference,/nix/store/z-reference",
            hash.to_typed_base32()
        )
        .into_bytes()
    );
    assert_eq!(
        fingerprint(Path::new("/nix/store/path"), &hash, 123, &[] as &[&str]),
        format!("1;/nix/store/path;{};123;", hash.to_typed_base32()).into_bytes()
    );
}

#[test]
fn fingerprint_signatures_bind_path_contents() {
    let key = NixKeypair::generate("attic-test").unwrap();
    let public = key.to_public_key();
    let path = Path::new("/nix/store/path");
    let hash = Hash::sha256_from_bytes(b"nar");
    let references = ["/nix/store/reference"];
    let signature = key.sign(&fingerprint(path, &hash, 123, &references));
    public
        .verify(&fingerprint(path, &hash, 123, &references), &signature)
        .unwrap();
    for message in [
        fingerprint(
            path,
            &Hash::sha256_from_bytes(b"tampered"),
            123,
            &references,
        ),
        fingerprint(path, &hash, 124, &references),
        fingerprint(path, &hash, 123, &[] as &[&str]),
    ] {
        assert!(public.verify(&message, &signature).is_err());
    }
    let message = fingerprint(path, &hash, 123, &references);
    assert!(
        public
            .verify(&message, &signature.replacen("attic-test:", "other:", 1))
            .is_err()
    );
    assert!(public.verify(&message, "attic-test:not base64!").is_err());
    let other = NixKeypair::generate("attic-test").unwrap();
    assert!(public.verify(&message, &other.sign(&message)).is_err());
}

#[cfg(unix)]
#[test]
fn nix_store_signature_verifies() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let temp = tempfile::tempdir().unwrap();
    let store = format!("local?root={}", temp.path().join("store").display());
    let run = |args: &[&str], input: Option<&[u8]>| {
        let mut command = Command::new("nix");
        command.args([
            "--extra-experimental-features",
            "nix-command",
            "--store",
            &store,
        ]);
        command
            .args(args)
            .env("NIX_CONF_DIR", temp.path())
            .env("NIX_USER_CONF_FILES", "/dev/null")
            .env("HOME", temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("Nix CLI required");
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        } else {
            drop(child.stdin.take());
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "Nix command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert!(
            diagnostics.is_empty()
                || (args.starts_with(&["store", "sign"]) && diagnostics == "added 1 signatures\n")
                || (args.starts_with(&["store", "verify"])
                    && diagnostics == format!("checking '{}'...\n", args.last().unwrap())),
            "Unexpected Nix diagnostics: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let secret = run(
        &["key", "generate-secret", "--key-name", "attic-test"],
        None,
    );
    let public = run(&["key", "convert-secret-to-public"], Some(&secret));
    let public: NixPublicKey = std::str::from_utf8(&public)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let key_file = temp.path().join("key");
    std::fs::write(&key_file, &secret).unwrap();
    let file = temp.path().join("input");
    std::fs::write(&file, b"signature interoperability").unwrap();
    let path = run(&["store", "add-file", file.to_str().unwrap()], None);
    let path = std::str::from_utf8(&path).unwrap().trim();
    run(
        &[
            "store",
            "sign",
            "--key-file",
            key_file.to_str().unwrap(),
            path,
        ],
        None,
    );
    let nar = run(&["store", "dump-path", path], None);
    let hash = Hash::sha256_from_bytes(&nar);
    let size = nar.len();
    let references: [&str; 0] = [];
    let info = run(&["path-info", "--sigs", path], None);
    let info = std::str::from_utf8(&info).unwrap();
    let signature = info
        .split_whitespace()
        .find(|value| value.starts_with("attic-test:"))
        .expect("Nix signature missing");
    public
        .verify(
            &fingerprint(Path::new(path), &hash, size, &references),
            signature,
        )
        .unwrap();
    assert!(
        public
            .verify(
                &fingerprint(Path::new(path), &hash, size + 1, &references),
                signature
            )
            .is_err()
    );
    run(
        &[
            "store",
            "verify",
            "--sigs-needed",
            "1",
            "--trusted-public-keys",
            &public.export(),
            path,
        ],
        None,
    );
}

#[test]
fn test_generate_key() {
    let keypair = NixKeypair::generate("attic-test").expect("Could not generate key");

    let export_priv = keypair.export_keypair();
    let export_pub = keypair.export_public_key();

    // re-import keypair
    let import = export_priv
        .parse::<NixKeypair>()
        .expect("Could not re-import generated key");

    assert_eq!(keypair.name, import.name);
    assert_eq!(keypair.keypair, import.keypair);

    // re-import public key
    let import_pub = export_pub
        .parse::<NixPublicKey>()
        .expect("Could not re-import public key");

    assert_eq!(keypair.name, import_pub.name);
    assert_eq!(keypair.keypair.pk, import_pub.public);

    // test the export functionality of NixPublicKey as well
    let export_pub2 = import_pub.export();
    let import_pub2 = export_pub2
        .parse::<NixPublicKey>()
        .expect("Could not re-import public key");

    assert_eq!(keypair.name, import_pub2.name);
    assert_eq!(keypair.keypair.pk, import_pub2.public);
}

#[test]
fn test_serde() {
    let json = "\"attic-test:x326WFy/JUl+MQnN1u9NPdWQPBbcVn2mwoIqSLS3DmQqZ8qT8rBSxxEnyhtl3jDouBqodlyfq6F+HsVhbTYPMA==\"";

    let keypair: NixKeypair = serde_json::from_str(json).expect("Could not deserialize keypair");

    let export = serde_json::to_string(&keypair).expect("Could not serialize keypair");

    eprintln!("Public Key: {}", keypair.export_public_key());

    assert_eq!(json, &export);
}

#[test]
fn test_import_public_key() {
    let cache_nixos_org = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";
    let import = cache_nixos_org
        .parse::<NixPublicKey>()
        .expect("Could not import public key");

    assert_eq!(cache_nixos_org, import.export());
}

#[test]
fn test_signing() {
    let keypair = NixKeypair::generate("attic-test").expect("Could not generate key");

    let public = keypair.to_public_key();

    let message = b"hello world";

    let signature = keypair.sign(message);

    keypair.verify(message, &signature).unwrap();
    public.verify(message, &signature).unwrap();

    keypair.verify(message, "attic-test:lo9EfNIL4eGRuNh7DTbAAffWPpI2SlYC/8uP7JnhgmfRIUNGhSbFe8qEaKN0mFS02TuhPpXFPNtRkFcCp0hGAQ==").unwrap_err();
}
