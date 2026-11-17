//! Upload verification policy and static public-key registry.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use attic::signing::NixPublicKey;
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

/// Scalar metadata attached to a registered key.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MetadataValue {
    String(String),
    Boolean(bool),
    Integer(i64),
    Float(f64),
}

/// Relationship required between registered metadata and token subject.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityMatch {
    #[default]
    Off,
    Warn,
    Enforce,
}

/// A detailed static key entry.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TrustedKey {
    pub public_key: String,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub metadata: BTreeMap<String, MetadataValue>,
}

/// Parsed key and attribution data.
#[derive(Clone, Debug)]
pub struct RegisteredKey {
    pub public_key: NixPublicKey,
    pub valid_from: Option<DateTime<FixedOffset>>,
    pub valid_until: Option<DateTime<FixedOffset>>,
    pub revoked: bool,
    pub metadata: BTreeMap<String, MetadataValue>,
}

/// Cache-local override of the server verification switch.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheVerification {
    pub enabled: bool,
}

/// Validated upload-verification configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "Settings")]
pub struct UploadVerification {
    pub enabled: bool,
    pub identity_match: IdentityMatch,
    pub identity_field: String,
    pub min_signatures: usize,
    pub caches: BTreeMap<String, CacheVerification>,
    pub trusted_keys: BTreeMap<String, RegisteredKey>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case", deny_unknown_fields)]
struct Settings {
    enabled: bool,
    identity_match: IdentityMatch,
    identity_field: Option<String>,
    min_signatures: Option<usize>,
    trusted_public_keys: Vec<String>,
    trusted_keys: Vec<TrustedKey>,
    caches: BTreeMap<String, CacheVerification>,
}

impl Default for UploadVerification {
    fn default() -> Self {
        Settings::default()
            .try_into()
            .expect("valid default policy")
    }
}

impl UploadVerification {
    pub fn enabled_for_cache(&self, cache: &str) -> bool {
        self.caches.get(cache).map_or(self.enabled, |c| c.enabled)
    }
}

impl TryFrom<Settings> for UploadVerification {
    type Error = anyhow::Error;

    fn try_from(settings: Settings) -> Result<Self> {
        let min_signatures = settings.min_signatures.unwrap_or(1);
        if min_signatures == 0 {
            bail!("upload-verification.min-signatures must be at least 1");
        }
        let mut keys = BTreeMap::new();
        for public_key in settings.trusted_public_keys {
            insert_key(
                &mut keys,
                TrustedKey {
                    public_key,
                    valid_from: None,
                    valid_until: None,
                    revoked: false,
                    metadata: BTreeMap::new(),
                },
            )?;
        }
        let mut detailed = std::collections::BTreeSet::new();
        for key in settings.trusted_keys {
            let name = key_name(&key.public_key)?;
            if !detailed.insert(name.clone()) {
                bail!("duplicate detailed trusted key: {name}");
            }
            insert_key(&mut keys, key)?;
        }
        Ok(Self {
            enabled: settings.enabled,
            identity_match: settings.identity_match,
            identity_field: settings
                .identity_field
                .unwrap_or_else(|| "identity".to_owned()),
            min_signatures,
            caches: settings.caches,
            trusted_keys: keys,
        })
    }
}

fn key_name(key: &str) -> Result<String> {
    key.parse::<NixPublicKey>()
        .map_err(|_| anyhow::anyhow!("invalid trusted public key"))?;
    Ok(key.split_once(':').expect("validated key").0.to_owned())
}

fn insert_key(keys: &mut BTreeMap<String, RegisteredKey>, key: TrustedKey) -> Result<()> {
    let name = key_name(&key.public_key)?;
    let public_key: NixPublicKey = key.public_key.parse().expect("validated key");
    if let Some(existing) = keys.get(&name)
        && existing.public_key.export() != public_key.export()
    {
        bail!("conflicting trusted public keys: {name}");
    }
    let parse_date = |value: Option<String>| -> Result<Option<DateTime<FixedOffset>>> {
        value
            .map(|value| DateTime::parse_from_rfc3339(&value).map_err(Into::into))
            .transpose()
    };
    let valid_from = parse_date(key.valid_from)?;
    let valid_until = parse_date(key.valid_until)?;
    if let (Some(from), Some(until)) = (valid_from, valid_until)
        && from >= until
    {
        bail!("invalid validity window for trusted key: {name}");
    }
    keys.insert(
        name,
        RegisteredKey {
            public_key,
            valid_from,
            valid_until,
            revoked: key.revoked,
            metadata: key.metadata,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attic::signing::NixKeypair;

    fn key() -> String {
        NixKeypair::generate("alice-1").unwrap().export_public_key()
    }

    #[test]
    fn defaults_and_cache_overrides() {
        let policy: UploadVerification = toml::from_str("[caches.private]\nenabled=true").unwrap();
        assert!(!policy.enabled_for_cache("public"));
        assert!(policy.enabled_for_cache("private"));
        assert_eq!(policy.identity_match, IdentityMatch::Off);
        assert_eq!(policy.identity_field, "identity");
        assert_eq!(policy.min_signatures, 1);
    }

    #[test]
    fn simple_and_detailed_keys_merge() {
        let key = key();
        let simple = format!("trusted-public-keys=[{key:?}]");
        let detailed = format!(
            "[[trusted-keys]]\npublic-key={key:?}\nrevoked=true\nvalid-from=\"2026-11-01T00:00:00Z\"\n[trusted-keys.metadata]\nidentity=\"alice\"\ncount=2\nactive=true"
        );
        for config in [&simple, &detailed, &format!("{simple}\n{detailed}")] {
            let policy: UploadVerification = toml::from_str(config).unwrap();
            assert_eq!(policy.trusted_keys.len(), 1);
        }
        let policy: UploadVerification = toml::from_str(&format!("{simple}\n{detailed}")).unwrap();
        let registered = &policy.trusted_keys["alice-1"];
        assert!(registered.revoked);
        assert!(registered.valid_from.is_some());
        assert_eq!(
            registered.metadata["identity"],
            MetadataValue::String("alice".into())
        );
    }

    #[test]
    fn rejects_conflicts_and_invalid_configuration() {
        let key = key();
        let other = self::key();
        for config in [
            format!("trusted-public-keys=[{key:?},{other:?}]"),
            format!("[[trusted-keys]]\npublic-key={key:?}\n[[trusted-keys]]\npublic-key={key:?}"),
            "trusted-public-keys=[\"malformed\"]".to_owned(),
            "min-signatures=0".to_owned(),
            format!("[[trusted-keys]]\npublic-key={key:?}\nvalid-until=\"invalid\""),
            format!(
                "[[trusted-keys]]\npublic-key={key:?}\n[trusted-keys.metadata]\nidentity=[\"alice\"]"
            ),
        ] {
            assert!(toml::from_str::<UploadVerification>(&config).is_err());
        }
    }
}
