//! Upload-only signing; local store signatures are not modified.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use attic::api::v1::upload_path::UploadPathNarInfo;
use attic::signing::{NixKeypair, NixPublicKey, fingerprint};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
pub struct Signing {
    pub key_file: Option<PathBuf>,
    pub command: Option<Vec<String>>,
    pub public_keys: Vec<String>,
    pub batch_size: usize,
    pub timeout: String,
}

impl Default for Signing {
    fn default() -> Self {
        Self {
            key_file: None,
            command: None,
            public_keys: Vec::new(),
            batch_size: 200,
            timeout: "60s".into(),
        }
    }
}

pub struct Signer {
    key: Option<NixKeypair>,
    config: Signing,
    public_keys: Vec<NixPublicKey>,
    timeout: std::time::Duration,
}

impl Signer {
    pub fn load(config: &Signing) -> Result<Self> {
        if config.batch_size == 0 {
            bail!("signing batch-size must be positive");
        }
        if config
            .command
            .as_ref()
            .is_some_and(|command| command.is_empty() || command[0].is_empty())
        {
            bail!("signing command cannot be empty");
        }
        let timeout =
            humantime::parse_duration(&config.timeout).context("Invalid signing timeout")?;
        if timeout.is_zero() {
            bail!("signing timeout must be positive");
        }
        let public_keys = config
            .public_keys
            .iter()
            .map(|key| {
                key.parse::<NixPublicKey>()
                    .map_err(|_| anyhow::anyhow!("Invalid signing public key"))
            })
            .collect::<Result<Vec<_>>>()?;
        if config.command.is_some() && public_keys.is_empty() {
            eprintln!(
                "Notice: signer responses rely on server verification; signing.public-keys is empty"
            );
        }
        let key = config
            .key_file
            .as_ref()
            .map(|path| {
                let metadata =
                    std::fs::metadata(path).context("Cannot inspect signing key file")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o044 != 0 {
                        eprintln!("Warning: signing key file is group/world readable");
                    }
                }
                let secret =
                    std::fs::read_to_string(path).context("Cannot read signing key file")?;
                secret
                    .trim()
                    .parse::<NixKeypair>()
                    .map_err(|_| anyhow::anyhow!("Malformed signing key file"))
            })
            .transpose()?;
        Ok(Self {
            key,
            config: config.clone(),
            public_keys,
            timeout,
        })
    }

    pub async fn sign(&self, paths: &mut [UploadPathNarInfo]) -> Result<()> {
        self.sign_key(paths);
        if self.config.command.is_none() {
            return Ok(());
        }
        for batch in paths.chunks_mut(self.config.batch_size) {
            let inputs: Vec<_> = batch.iter().map(|path| {
                let bytes = path_fingerprint(path);
                serde_json::json!({"storePath":path.store_path,"narHash":path.nar_hash.to_typed_base32(),"narSize":path.nar_size,
                    "references":full_references(path),"fingerprint":String::from_utf8(bytes).expect("UTF-8 fingerprint")})
            }).collect();
            let input = serde_json::to_vec(&serde_json::json!({"version":1,"paths":inputs}))?;
            let output = tokio::time::timeout(self.timeout, self.invoke(&input))
                .await
                .context("Signing command timed out")??;
            #[derive(Deserialize)]
            struct Response {
                signatures: Vec<String>,
            }
            let response: Response = serde_json::from_slice(&output)
                .map_err(|_| anyhow::anyhow!("Invalid signing command JSON"))?;
            if response.signatures.len() != batch.len() {
                bail!("Signing command response length mismatch");
            }
            for (path, signature) in batch.iter().zip(&response.signatures) {
                let (name, payload) = signature
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("Malformed signer signature"))?;
                if name.is_empty() {
                    bail!("Malformed signer signature name");
                }
                if STANDARD
                    .decode(payload)
                    .map_or(true, |bytes| bytes.len() != 64)
                {
                    bail!("Malformed signer signature bytes");
                }
                if !self.public_keys.is_empty() {
                    let bytes = path_fingerprint(path);
                    if !self
                        .public_keys
                        .iter()
                        .any(|key| key.verify(&bytes, signature).is_ok())
                    {
                        bail!("Signer signature failed public-key verification");
                    }
                }
            }
            for (path, signature) in batch.iter_mut().zip(response.signatures) {
                if !path.sigs.contains(&signature) {
                    path.sigs.push(signature);
                }
            }
        }
        Ok(())
    }

    async fn invoke(&self, input: &[u8]) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let command = self.config.command.as_ref().expect("configured command");
        let mut child = tokio::process::Command::new(&command[0])
            .args(&command[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Cannot start signing command")?;
        let mut stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let mut stderr = child.stderr.take().expect("stderr");
        let write = async move {
            stdin.write_all(input).await?;
            stdin.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let read = async {
            let mut bytes = Vec::new();
            stdout.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
            if bytes.len() > 1024 * 1024 {
                bail!("Signer output exceeds limit");
            }
            Ok::<_, anyhow::Error>(bytes)
        };
        let errors = async {
            let mut retained = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let size = stderr.read(&mut buffer).await?;
                if size == 0 {
                    break;
                }
                let keep = size.min(65536 - retained.len());
                retained.extend_from_slice(&buffer[..keep]);
            }
            Ok::<_, anyhow::Error>(retained)
        };
        let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
        let ((), output, errors, status) = tokio::try_join!(write, read, errors, wait)?;
        if !errors.is_empty() {
            eprintln!(
                "Signer stderr: {}",
                String::from_utf8_lossy(&errors).escape_default()
            );
        }
        if !status.success() {
            bail!("Signing command exited unsuccessfully");
        }
        Ok(output)
    }

    fn sign_key(&self, paths: &mut [UploadPathNarInfo]) {
        let Some(key) = &self.key else {
            return;
        };
        let public = key.export_public_key();
        let name = public.split_once(':').expect("public key format").0;
        for path in paths {
            if path.sigs.iter().any(|signature| {
                signature
                    .split_once(':')
                    .is_some_and(|(existing, _)| existing == name)
            }) {
                continue;
            }
            let bytes = path_fingerprint(path);
            path.sigs.push(key.sign(&bytes));
        }
    }
}

fn full_references(path: &UploadPathNarInfo) -> Vec<PathBuf> {
    let store_dir = Path::new(&path.store_path)
        .parent()
        .expect("store path directory");
    let mut references: Vec<_> = path
        .references
        .iter()
        .map(|reference| store_dir.join(reference))
        .collect();
    references.sort_unstable();
    references
}

fn path_fingerprint(path: &UploadPathNarInfo) -> Vec<u8> {
    fingerprint(
        Path::new(&path.store_path),
        &path.nar_hash,
        path.nar_size,
        &full_references(path),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload() -> UploadPathNarInfo {
        serde_json::from_value(serde_json::json!({
            "cache":"test", "store_path_hash":"00000000000000000000000000000000",
            "store_path":"/nix/store/00000000000000000000000000000000-example", "references":[],
            "nar_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000", "nar_size":3, "sigs":["host:preserved"]
        })).unwrap()
    }

    #[test]
    fn key_file_loading_and_configuration_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, "private-material-not-a-key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = Signing {
            key_file: Some(path.clone()),
            ..Default::default()
        };
        let error = Signer::load(&config).err().unwrap();
        assert_eq!(error.to_string(), "Malformed signing key file");
        let key = NixKeypair::generate("file").unwrap();
        std::fs::write(&path, key.export_keypair()).unwrap();
        assert_eq!(
            Signer::load(&config)
                .unwrap()
                .key
                .unwrap()
                .export_public_key(),
            key.export_public_key()
        );
        for config in [
            Signing {
                batch_size: 0,
                ..Default::default()
            },
            Signing {
                command: Some(vec![]),
                ..Default::default()
            },
            Signing {
                timeout: "0s".into(),
                ..Default::default()
            },
        ] {
            assert!(Signer::load(&config).is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_batch_verifies_and_preserves_key_signature() {
        let directory = tempfile::tempdir().unwrap();
        let captured = directory.path().join("input.jsonl");
        let external = NixKeypair::generate("external").unwrap();
        let signature = external.sign(&path_fingerprint(&upload()));
        let response =
            serde_json::to_string(&serde_json::json!({"signatures":[signature]})).unwrap();
        let config = Signing {
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                "cat >>\"$2\"; printf '\\n' >>\"$2\"; printf '%s' \"$1\"".into(),
                "signer".into(),
                response,
                captured.to_str().unwrap().into(),
            ]),
            public_keys: vec![external.export_public_key()],
            batch_size: 1,
            ..Default::default()
        };
        let mut signer = Signer::load(&config).unwrap();
        signer.key = Some(NixKeypair::generate("local").unwrap());
        let mut paths = vec![upload(), upload()];
        signer.sign(&mut paths).await.unwrap();
        let input = std::fs::read_to_string(captured).unwrap();
        let batches: Vec<serde_json::Value> = input
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(batches.len(), 2);
        for batch in batches {
            assert_eq!(batch["version"], 1);
            assert_eq!(batch["paths"].as_array().unwrap().len(), 1);
            let path = &batch["paths"][0];
            assert_eq!(path["storePath"], upload().store_path);
            assert_eq!(
                path["fingerprint"],
                String::from_utf8(path_fingerprint(&upload())).unwrap()
            );
            external
                .verify(path["fingerprint"].as_str().unwrap().as_bytes(), &signature)
                .unwrap();
        }
        for path in paths {
            assert_eq!(path.sigs.len(), 3);
            assert_eq!(path.sigs[0], "host:preserved");
            assert!(path.sigs[1].starts_with("local:"));
            external
                .verify(&path_fingerprint(&path), &path.sigs[2])
                .unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_errors_abort_signing() {
        let key = NixKeypair::generate("external").unwrap();
        for (script, expected) in [
            (
                "cat >/dev/null; printf invalid",
                "Invalid signing command JSON",
            ),
            (
                "cat >/dev/null; printf '{\"signatures\":[]}'",
                "length mismatch",
            ),
            ("cat >/dev/null; exit 1", "exited unsuccessfully"),
            (
                "cat >/dev/null; printf '{\"signatures\":[\"external:bad\"]}'",
                "Malformed signer signature bytes",
            ),
        ] {
            let config = Signing {
                command: Some(vec!["sh".into(), "-c".into(), script.into()]),
                public_keys: vec![key.export_public_key()],
                ..Default::default()
            };
            let mut paths = vec![upload()];
            let error = Signer::load(&config)
                .unwrap()
                .sign(&mut paths)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert_eq!(paths[0].sigs, ["host:preserved"]);
        }
        let response = serde_json::to_string(
            &serde_json::json!({"signatures":[key.sign(b"wrong fingerprint")]}),
        )
        .unwrap();
        let config = Signing {
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                "cat >/dev/null; printf '%s' \"$1\"".into(),
                "signer".into(),
                response,
            ]),
            public_keys: vec![key.export_public_key()],
            ..Default::default()
        };
        let error = Signer::load(&config)
            .unwrap()
            .sign(&mut [upload()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("public-key verification"));
        let config = Signing {
            command: Some(vec!["sleep".into(), "2".into()]),
            timeout: "20ms".into(),
            public_keys: vec![key.export_public_key()],
            ..Default::default()
        };
        let error = Signer::load(&config)
            .unwrap()
            .sign(&mut [upload()])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn preserves_signatures_and_skips_existing_name() {
        let key = NixKeypair::generate("person").unwrap();
        let mut signer = Signer::load(&Signing::default()).unwrap();
        signer.key = Some(key);
        let mut paths = vec![upload()];
        paths[0].references = vec!["11111111111111111111111111111111-ref".into()];
        signer.sign(&mut paths).await.unwrap();
        assert_eq!(paths[0].sigs.len(), 2);
        let bytes = fingerprint(
            Path::new(&paths[0].store_path),
            &paths[0].nar_hash,
            paths[0].nar_size,
            &[Path::new("/nix/store/11111111111111111111111111111111-ref")],
        );
        signer
            .key
            .as_ref()
            .unwrap()
            .verify(&bytes, &paths[0].sigs[1])
            .unwrap();
        signer.sign(&mut paths).await.unwrap();
        assert_eq!(paths[0].sigs.len(), 2);
        assert_eq!(paths[0].sigs[0], "host:preserved");
        Signer::load(&Signing::default())
            .unwrap()
            .sign(&mut paths)
            .await
            .unwrap();
        assert_eq!(paths[0].sigs.len(), 2);
    }
}
