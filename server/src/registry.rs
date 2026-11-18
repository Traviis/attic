//! Trusted-key source snapshots and fail-closed merge.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::config::upload_verification::{RegisteredKey, TrustedKey, insert_key};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    public_key: String,
    valid_from: Option<String>,
    valid_until: Option<String>,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    metadata: BTreeMap<String, crate::config::upload_verification::MetadataValue>,
}

#[derive(Deserialize)]
struct Document {
    version: u32,
    keys: Vec<serde_json::Value>,
}

pub(crate) fn parse_source(bytes: &[u8]) -> Result<BTreeMap<String, RegisteredKey>> {
    let document: Document = serde_json::from_slice(bytes)?;
    if document.version != 1 {
        bail!("unsupported registry version: {}", document.version);
    }
    let mut keys = BTreeMap::new();
    let mut rejected = BTreeSet::new();
    for entry in document.keys {
        let parsed = (|| -> Result<_> {
            let entry: Entry = serde_json::from_value(entry)?;
            let mut one = BTreeMap::new();
            insert_key(
                &mut one,
                TrustedKey {
                    public_key: entry.public_key,
                    valid_from: entry.valid_from,
                    valid_until: entry.valid_until,
                    revoked: entry.revoked,
                    metadata: entry.metadata,
                },
            )?;
            let (name, mut key) = one.pop_first().expect("one parsed key");
            key.detailed = true;
            Ok((name, key))
        })();
        match parsed {
            Ok((name, key)) => {
                if !rejected.contains(&name) {
                    match keys.entry(name.clone()) {
                        std::collections::btree_map::Entry::Occupied(entry) => {
                            entry.remove();
                            rejected.insert(name.clone());
                            tracing::error!(
                                key_name = name,
                                "Duplicate detailed registry entry rejected"
                            );
                        }
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            entry.insert(key);
                        }
                    }
                }
            }
            Err(error) => tracing::error!(%error, "Invalid registry entry skipped"),
        }
    }
    Ok(keys)
}

#[derive(Debug, Default)]
pub(crate) struct Source {
    pub keys: BTreeMap<String, RegisteredKey>,
}

impl Source {
    pub fn replace(&mut self, bytes: &[u8]) -> Result<()> {
        let keys = parse_source(bytes)?;
        if keys.is_empty() && !self.keys.is_empty() {
            bail!("registry source returned zero keys after a nonempty snapshot");
        }
        self.keys = keys;
        Ok(())
    }
}

pub(crate) fn merge<'a>(
    sources: impl IntoIterator<Item = (&'static str, &'a BTreeMap<String, RegisteredKey>)>,
) -> (BTreeMap<String, RegisteredKey>, BTreeSet<String>) {
    let mut keys: BTreeMap<String, RegisteredKey> = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for (source, entries) in sources {
        for (name, key) in entries {
            if conflicts.contains(name) {
                continue;
            }
            if let Some(existing) = keys.get(name) {
                if existing.public_key.export() != key.public_key.export() {
                    keys.remove(name);
                    conflicts.insert(name.clone());
                    crate::audit::emit(
                        &serde_json::json!({"event":"registry.conflict","key_name":name,"source":source}),
                    );
                } else if existing.detailed && key.detailed {
                    // Multiple detailed entries cannot grant ambiguous validity or metadata.
                    keys.remove(name);
                    conflicts.insert(name.clone());
                    tracing::error!(
                        key_name = name,
                        "Duplicate detailed registry entry rejected"
                    );
                } else if key.detailed {
                    let mut key = key.clone();
                    key.source = source;
                    keys.insert(name.clone(), key);
                }
            } else {
                let mut key = key.clone();
                key.source = source;
                keys.insert(name.clone(), key);
            }
        }
    }
    (keys, conflicts)
}

#[derive(Debug)]
pub(crate) struct Registry {
    policy: crate::config::upload_verification::UploadVerification,
    file: Source,
    command: Source,
    unknown_refreshes: std::collections::VecDeque<std::time::Instant>,
    refreshed: std::time::Instant,
    file_stamp: Option<(std::time::SystemTime, u64)>,
}

impl Registry {
    pub fn new(policy: crate::config::upload_verification::UploadVerification) -> Self {
        Self {
            policy,
            file: Source::default(),
            command: Source::default(),
            unknown_refreshes: Default::default(),
            refreshed: std::time::Instant::now(),
            file_stamp: None,
        }
    }

    pub async fn refresh(&mut self) {
        let Some(resolver) = self.policy.resolver.clone() else {
            return;
        };
        self.refreshed = std::time::Instant::now();
        if let Some(path) = resolver.file {
            self.file_stamp = file_stamp(&path).await;
            let result = tokio::fs::read(path)
                .await
                .map_err(anyhow::Error::from)
                .and_then(|bytes| self.file.replace(&bytes));
            if let Err(error) = result {
                refresh_failed("file", error);
            }
        }
        if let Some(command) = resolver.command {
            let result = run_command(&command, resolver.command_timeout)
                .await
                .and_then(|bytes| self.command.replace(&bytes));
            if let Err(error) = result {
                refresh_failed("command", error);
            }
        }
    }

    pub async fn refresh_if_due(&mut self) {
        let Some(resolver) = &self.policy.resolver else {
            return;
        };
        let changed = if let Some(path) = &resolver.file {
            file_stamp(path).await != self.file_stamp
        } else {
            false
        };
        if changed || self.refreshed.elapsed() >= resolver.refresh_interval {
            self.refresh().await;
        }
    }

    pub async fn for_signatures(
        &mut self,
        signatures: &[String],
    ) -> crate::config::upload_verification::UploadVerification {
        self.refresh_if_due().await;
        let policy = self.policy();
        let unknown = signatures
            .iter()
            .filter_map(|signature| signature.split_once(':'))
            .any(|(name, _)| !policy.trusted_keys.contains_key(name));
        if unknown && let Some(resolver) = &self.policy.resolver {
            let limit = resolver
                .unknown_key_refresh_limit
                .strip_suffix("/min")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let now = std::time::Instant::now();
            while self
                .unknown_refreshes
                .front()
                .is_some_and(|time| now.duration_since(*time).as_secs() >= 60)
            {
                self.unknown_refreshes.pop_front();
            }
            if self.unknown_refreshes.len() < limit {
                self.unknown_refreshes.push_back(now);
                self.refresh().await;
                return self.policy();
            }
        }
        policy
    }

    pub fn policy(&self) -> crate::config::upload_verification::UploadVerification {
        let mut policy = self.policy.clone();
        policy.trusted_keys = merge([
            ("static", &self.policy.trusted_keys),
            ("file", &self.file.keys),
            ("command", &self.command.keys),
        ])
        .0;
        policy
    }
}

async fn file_stamp(path: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
    let metadata = tokio::fs::metadata(path).await.ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

fn refresh_failed(source: &str, error: anyhow::Error) {
    tracing::error!(source, %error, "Registry refresh failed");
    crate::audit::emit(
        &serde_json::json!({"event":"registry.refresh_failed","source":source,"reason":error.to_string()}),
    );
}

async fn run_command(command: &[String], timeout: std::time::Duration) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty resolver command"))?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    tokio::time::timeout(timeout, async move {
        let output = async {
            let mut bytes = Vec::new();
            stdout.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
            if bytes.len() > 1024 * 1024 { bail!("resolver output exceeds size limit"); }
            Ok::<_, anyhow::Error>(bytes)
        };
        let errors = async {
            let mut stderr = stderr;
            let mut retained = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = stderr.read(&mut buffer).await?;
                if count == 0 { break; }
                let keep = count.min(65536 - retained.len());
                retained.extend_from_slice(&buffer[..keep]);
            }
            if !retained.is_empty() {
                tracing::warn!(stderr = %String::from_utf8_lossy(&retained), "Registry command stderr");
            }
            Ok::<_, anyhow::Error>(())
        };
        let status = async { Ok::<_, anyhow::Error>(child.wait().await?) };
        let (output, (), status) = tokio::try_join!(output, errors, status)?;
        if !status.success() { bail!("resolver command exited unsuccessfully"); }
        Ok(output)
    })
    .await
    .map_err(|_| anyhow::anyhow!("resolver command timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use attic::signing::NixKeypair;

    fn document(key: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"version":1,"keys":[{"publicKey":key,"metadata":{"identity":"alice","kind":"host","number":2}}]})).unwrap()
    }

    #[test]
    fn malformed_entries_do_not_discard_valid_keys() {
        let key = NixKeypair::generate("alice").unwrap().export_public_key();
        let mut doc: serde_json::Value = serde_json::from_slice(&document(&key)).unwrap();
        doc["keys"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"publicKey":"invalid"}));
        let keys = parse_source(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys["alice"].public_key.export(), key);
        assert_eq!(
            keys["alice"].metadata["kind"],
            crate::config::upload_verification::MetadataValue::String("host".into())
        );
    }

    #[tokio::test]
    async fn file_reload_and_unknown_refresh_rate_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("keys.json");
        let alice = NixKeypair::generate("alice").unwrap().export_public_key();
        tokio::fs::write(&path, document(&alice)).await.unwrap();
        let policy = toml::from_str(&format!(
            "[resolver]\nfile={:?}\nunknown-key-refresh-limit=\"1/min\"",
            path.to_str().unwrap()
        ))
        .unwrap();
        let mut registry = Registry::new(policy);
        registry.refresh().await;
        assert!(registry.policy().trusted_keys.contains_key("alice"));
        let bob = NixKeypair::generate("bob").unwrap().export_public_key();
        tokio::fs::write(&path, document(&bob)).await.unwrap();
        registry.refresh_if_due().await;
        assert!(registry.policy().trusted_keys.contains_key("bob"));
        registry.for_signatures(&["unknown:value".into()]).await;
        assert_eq!(registry.unknown_refreshes.len(), 1);
        registry.for_signatures(&["unknown:value".into()]).await;
        assert_eq!(registry.unknown_refreshes.len(), 1);
        tokio::fs::write(&path, b"invalid").await.unwrap();
        registry.refresh().await;
        assert!(registry.policy().trusted_keys.contains_key("bob"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_snapshot_survives_failures_and_merges_static_keys() {
        let alice = NixKeypair::generate("alice").unwrap().export_public_key();
        let bob = NixKeypair::generate("bob").unwrap().export_public_key();
        let mut policy: crate::config::upload_verification::UploadVerification =
            toml::from_str(&format!(
                "trusted-public-keys = [{alice:?}, {bob:?}]\n[resolver]\ncommand = [\"false\"]"
            ))
            .unwrap();
        let resolver = policy.resolver.as_mut().unwrap();
        resolver.command = Some(vec![
            "printf".into(),
            "%s".into(),
            String::from_utf8(document(&alice)).unwrap(),
        ]);
        let mut registry = Registry::new(policy);
        registry.refresh().await;
        let keys = registry.policy().trusted_keys;
        assert_eq!(keys.len(), 2);
        assert_eq!(keys["alice"].source, "command");
        assert_eq!(keys["bob"].source, "static");
        assert!(keys["alice"].metadata.contains_key("identity"));
        for output in [
            "invalid",
            r#"{"version":2,"keys":[]}"#,
            r#"{"version":1,"keys":[]}"#,
        ] {
            registry.policy.resolver.as_mut().unwrap().command =
                Some(vec!["printf".into(), "%s".into(), output.into()]);
            registry.refresh().await;
            assert_eq!(
                registry.policy().trusted_keys["alice"].public_key.export(),
                alice
            );
        }
        registry.policy.resolver.as_mut().unwrap().command = Some(vec!["false".into()]);
        registry.refresh().await;
        assert_eq!(
            registry.policy().trusted_keys["alice"].public_key.export(),
            alice
        );
        registry.file.replace(&document(&alice)).unwrap();
        assert!(!registry.policy().trusted_keys.contains_key("alice"));
        assert!(registry.policy().trusted_keys.contains_key("bob"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_failure_timeout_and_size_are_errors() {
        let timeout = std::time::Duration::from_secs(2);
        assert!(run_command(&["false".into()], timeout).await.is_err());
        assert!(
            run_command(
                &["sleep".into(), "2".into()],
                std::time::Duration::from_millis(20)
            )
            .await
            .is_err()
        );
        assert_eq!(
            run_command(&["printf".into(), "hello".into()], timeout)
                .await
                .unwrap(),
            b"hello"
        );
        let error = run_command(
            &[
                "head".into(),
                "-c".into(),
                "1048577".into(),
                "/dev/zero".into(),
            ],
            timeout,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "resolver output exceeds size limit");
    }

    #[test]
    fn failures_keep_last_known_good_and_conflicts_fail_closed() {
        let key = NixKeypair::generate("alice").unwrap().export_public_key();
        let other = NixKeypair::generate("alice").unwrap().export_public_key();
        let mut source = Source::default();
        source.replace(&document(&key)).unwrap();
        for bytes in [
            b"invalid".as_slice(),
            br#"{"version":2,"keys":[]}"#,
            br#"{"version":1,"keys":[]}"#,
        ] {
            assert!(source.replace(bytes).is_err());
            assert_eq!(source.keys["alice"].public_key.export(), key);
        }
        let other = parse_source(&document(&other)).unwrap();
        let (keys, conflicts) = merge([("file", &source.keys), ("command", &other)]);
        assert!(keys.is_empty());
        assert!(conflicts.contains("alice"));
    }
}
