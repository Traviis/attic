//! Built-in upload signature checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use attic::{api::v1::upload_path::UploadPathNarInfo, signing::fingerprint};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::upload_verification::{IdentityMatch, MetadataValue, UploadVerification};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignatureStatus {
    Valid,
    UnknownKey,
    Invalid,
    Expired,
    Revoked,
    Malformed,
}

#[derive(Debug, Serialize)]
pub(crate) struct SignatureResult {
    pub key_name: String,
    pub value: String,
    pub status: SignatureStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, MetadataValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    pub identity_mismatch: bool,
}

#[derive(Debug)]
pub(crate) struct Decision {
    pub signatures: Vec<SignatureResult>,
    pub valid_count: usize,
    pub reason: Option<String>,
}

fn request_fingerprint(upload: &UploadPathNarInfo) -> Vec<u8> {
    let path = Path::new(&upload.store_path);
    let store_dir = path.parent().unwrap_or(Path::new("/nix/store"));
    let references: Vec<_> = upload
        .references
        .iter()
        .map(|r| store_dir.join(r))
        .collect();
    fingerprint(path, &upload.nar_hash, upload.nar_size, &references)
}

pub(crate) fn verify(
    policy: &UploadVerification,
    upload: &UploadPathNarInfo,
    subject: Option<&str>,
    now: DateTime<Utc>,
) -> Decision {
    let mut decision = Decision {
        signatures: Vec::new(),
        valid_count: 0,
        reason: None,
    };
    if !policy.enabled_for_cache(upload.cache.as_str()) {
        return decision;
    }
    let fingerprint = request_fingerprint(upload);
    let mut valid_keys = BTreeSet::new();
    let mut identity_matches = false;
    for value in &upload.sigs {
        let (name, payload) = value.split_once(':').unwrap_or((value, ""));
        let key = policy.trusted_keys.get(name);
        let malformed = name.is_empty()
            || STANDARD
                .decode(payload)
                .map_or(true, |bytes| bytes.len() != 64);
        let status = if malformed {
            SignatureStatus::Malformed
        } else if let Some(key) = key {
            if key.revoked {
                SignatureStatus::Revoked
            } else if key.valid_from.is_some_and(|from| now < from)
                || key.valid_until.is_some_and(|until| now >= until)
            {
                SignatureStatus::Expired
            } else if key.public_key.verify(&fingerprint, value).is_err() {
                SignatureStatus::Invalid
            } else {
                SignatureStatus::Valid
            }
        } else {
            SignatureStatus::UnknownKey
        };
        let matches = key.and_then(|key| key.metadata.get(&policy.identity_field))
            .is_some_and(|identity| matches!(identity, MetadataValue::String(identity) if Some(identity.as_str()) == subject));
        if status == SignatureStatus::Valid {
            valid_keys.insert(name);
            identity_matches |= matches;
        }
        decision.signatures.push(SignatureResult {
            key_name: name.to_owned(),
            value: value.clone(),
            status,
            public_key: key.map(|key| key.public_key.export()),
            metadata: key.map(|key| key.metadata.clone()),
            source: key.map(|_| "static"),
            identity_mismatch: key.is_some() && !matches,
        });
    }
    decision.valid_count = valid_keys.len();
    decision.reason = if upload.sigs.is_empty() {
        Some("no signature".to_owned())
    } else if decision.valid_count < policy.min_signatures {
        Some(format!(
            "too few valid signatures: {} required, {} valid",
            policy.min_signatures, decision.valid_count
        ))
    } else if policy.identity_match == IdentityMatch::Enforce && !identity_matches {
        Some("identity mismatch".to_owned())
    } else {
        None
    };
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use attic::{api::v1::upload_path::UploadPathNarInfo, hash::Hash, signing::NixKeypair};
    use chrono::Utc;

    fn upload() -> UploadPathNarInfo {
        UploadPathNarInfo {
            cache: "private".parse().unwrap(),
            store_path_hash: attic::nix_store::StorePathHash::new(
                "00000000000000000000000000000000".into(),
            )
            .unwrap(),
            store_path: "/nix/store/00000000000000000000000000000000-example".into(),
            references: vec![],
            system: None,
            deriver: None,
            sigs: vec![],
            ca: None,
            nar_hash: Hash::sha256_from_bytes(b"nar"),
            nar_size: 3,
        }
    }

    #[test]
    fn counts_distinct_valid_keys_and_records_unknown() {
        let alice = NixKeypair::generate("alice").unwrap();
        let host = NixKeypair::generate("host").unwrap();
        let policy = toml::from_str(&format!(
            "enabled=true\nmin-signatures=2\ntrusted-public-keys=[{:?},{:?}]",
            alice.export_public_key(),
            host.export_public_key()
        ))
        .unwrap();
        let mut upload = upload();
        let message = request_fingerprint(&upload);
        let signature = alice.sign(&message);
        upload.sigs = vec![signature.clone(), signature];
        let decision = verify(&policy, &upload, Some("alice"), Utc::now());
        assert_eq!(decision.valid_count, 1);
        assert!(decision.reason.is_some());
        upload.sigs.push(host.sign(&message));
        upload
            .sigs
            .push(NixKeypair::generate("unknown").unwrap().sign(&message));
        let decision = verify(&policy, &upload, Some("alice"), Utc::now());
        assert!(decision.reason.is_none());
        assert_eq!(decision.valid_count, 2);
        assert_eq!(decision.signatures.len(), 4);
        assert_eq!(decision.signatures[3].status, SignatureStatus::UnknownKey);
    }

    #[test]
    fn classifies_invalid_expired_revoked_and_malformed() {
        let key = NixKeypair::generate("alice").unwrap();
        let mut upload = upload();
        upload.sigs = vec![key.sign(&request_fingerprint(&upload))];
        for (settings, expected) in [
            ("revoked=true", SignatureStatus::Revoked),
            (
                "valid-until=\"2000-01-01T00:00:00Z\"",
                SignatureStatus::Expired,
            ),
            (
                "valid-from=\"2100-01-01T00:00:00Z\"",
                SignatureStatus::Expired,
            ),
            ("", SignatureStatus::Valid),
        ] {
            let policy = toml::from_str(&format!(
                "enabled=true\n[[trusted-keys]]\npublic-key={:?}\n{settings}",
                key.export_public_key()
            ))
            .unwrap();
            assert_eq!(
                verify(&policy, &upload, None, Utc::now()).signatures[0].status,
                expected
            );
        }
        let policy = toml::from_str(&format!(
            "enabled=true\ntrusted-public-keys=[{:?}]",
            key.export_public_key()
        ))
        .unwrap();
        upload.sigs = vec![
            "alice:!".into(),
            "no-colon".into(),
            NixKeypair::generate("alice").unwrap().sign(b"wrong"),
        ];
        let decision = verify(&policy, &upload, None, Utc::now());
        assert_eq!(decision.signatures[0].status, SignatureStatus::Malformed);
        assert_eq!(decision.signatures[1].status, SignatureStatus::Malformed);
        assert_eq!(decision.signatures[2].status, SignatureStatus::Invalid);
    }

    #[test]
    fn identity_uses_configured_metadata_and_disabled_checks_are_empty() {
        let key = NixKeypair::generate("alice").unwrap();
        let mut upload = upload();
        upload.sigs = vec![key.sign(&request_fingerprint(&upload))];
        for mode in ["off", "warn", "enforce"] {
            let policy = toml::from_str(&format!("enabled=true\nidentity-match={mode:?}\nidentity-field=\"owner\"\n[[trusted-keys]]\npublic-key={:?}\nmetadata={{owner=\"alice\"}}", key.export_public_key())).unwrap();
            assert!(
                verify(&policy, &upload, Some("alice"), Utc::now())
                    .reason
                    .is_none()
            );
            let other = verify(&policy, &upload, Some("bob"), Utc::now());
            assert_eq!(other.reason.is_some(), mode == "enforce");
            assert!(other.signatures[0].identity_mismatch);
        }
        let disabled = verify(&Default::default(), &upload, None, Utc::now());
        assert!(disabled.reason.is_none());
        assert!(disabled.signatures.is_empty());
    }
}
