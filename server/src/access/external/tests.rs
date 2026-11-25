use super::*;
use attic::cache::CacheName;
use jwt_simple::prelude::{Claims, RSAKeyPairLike, RS256KeyPair};
use serde_json::json;

fn config() -> ExternalJwtConfig {
    serde_json::from_value(json!({
        "issuer": "https://identity.example/attic", "audience": "attic",
        "algorithms": ["RS256"], "mappings": [
            {"claim":"groups", "value":"readers", "caches":{"team-*":{"r":1}}},
            {"claim":"roles", "value":"writers", "caches":{"team-*":{"w":1}, "team-special":{"d":1}}},
            {"claim":"groups", "value":"readers", "caches":{"team-ci-*":{"cc":1}}}
        ]
    })).unwrap()
}

#[test]
fn mapping_preserves_precedence_and_discards_external_grants() {
    let claims = Claims::with_custom_claims(json!({
        "groups":["readers"], "roles":["writers"],
        attic_token::CLAIM_NAMESPACE: {"caches":{"*":{"cd":1}}}
    }), jwt_simple::prelude::Duration::from_secs(60))
        .with_issuer("https://identity.example/attic").with_subject("alice");
    let token = config().map_claims(claims);
    let permission = token.get_permission_for_cache(&CacheName::new("team-ci-one".into()).unwrap());
    assert!(permission.pull && permission.push); // same pattern grants merged
    assert!(!permission.create_cache); // first wildcard match, not union
    let permission = token.get_permission_for_cache(&CacheName::new("team-special".into()).unwrap());
    assert!(permission.delete && !permission.pull); // exact overrides wildcard
    assert!(!token.get_permission_for_cache(&CacheName::new("other".into()).unwrap()).destroy_cache);
    assert_eq!(token.sub(), Some("alice"));
    assert_eq!(token.principal(), Some("[\"https://identity.example/attic\",\"alice\"]"));
    let opaque = serde_json::to_value(token.opaque_claims()).unwrap();
    assert_eq!(opaque["iss"], "https://identity.example/attic");
    assert_eq!(opaque["sub"], "alice");
}

#[test]
fn malformed_group_claim_never_grants_permissions() {
    for groups in [json!("readers"), json!(["readers", 1]), json!(null)] {
        let claims = Claims::with_custom_claims(json!({"groups":groups}), jwt_simple::prelude::Duration::from_secs(60));
        let token = config().map_claims(claims);
        assert!(!token.get_permission_for_cache(&CacheName::new("team-one".into()).unwrap()).can_discover());
    }
}

#[test]
fn rejects_unsafe_configuration_urls() {
    for url in ["http://localhost:8200", "http://identity.example", "https://user:pass@identity.example", "https://identity.example/#fragment", "https://identity.example/?q=1", "file:///etc/passwd"] {
        assert!(trusted_url(url).is_err(), "{url}");
    }
    for url in ["http://127.0.0.1:8200/v1/identity/oidc/provider/attic", "http://[::1]:8200", "https://identity.example/oidc"] {
        assert!(trusted_url(url).is_ok(), "{url}");
    }
    let mut config = config();
    config.algorithms = vec!["HS256".into()];
    assert!(config.validate().is_err());
    config.algorithms = vec!["RS256".into()];
    config.audience.clear();
    assert!(config.validate().is_err());
}

#[test]
fn jwks_rejects_duplicate_and_incompatible_rsa_keys() {
    // A real public modulus is not necessary to exercise pre-verification constraints.
    let jwk = json!({"kty":"RSA", "kid":"one", "n":URL_SAFE_NO_PAD.encode([0x81;256]),"e":"AQAB", "alg":"RS256", "use":"sig", "key_ops":["verify"]});
    assert!(parse_keys(serde_json::from_value(json!({"keys":[jwk.clone()]})).unwrap()).is_ok());
    assert!(parse_keys(serde_json::from_value(json!({"keys":[jwk.clone(),jwk.clone()]})).unwrap()).is_err());
    for (field, value) in [("alg", json!("HS256")), ("use", json!("enc")), ("key_ops", json!(["sign"]))] {
        let mut incompatible = jwk.clone();
        incompatible[field] = value;
        assert!(parse_keys(serde_json::from_value(json!({"keys":[incompatible]})).unwrap()).is_err());
    }
}

#[tokio::test]
async fn verifies_required_claims_algorithm_signature_and_cache_expiry() {
    let external = ExternalJwt::new(config()).unwrap();
    let key = RS256KeyPair::generate(2048).unwrap().with_key_id("test");
    {
        let mut cache = external.cache.lock().await;
        cache.keys.insert("test".into(), key.public_key());
        cache.fetched = Some(Instant::now());
        cache.attempted = Some(Instant::now());
    }
    let claims = Claims::with_custom_claims(json!({"groups":["readers"]}), jwt_simple::prelude::Duration::from_secs(60))
        .with_issuer(&external.config.issuer).with_audience("attic").with_subject("alice");
    assert!(external.verify(&key.sign(claims.clone()).unwrap()).await.is_ok());
    for mutation in ["iss", "aud", "exp", "sub", "empty-sub", "nbf"] {
        let mut invalid = claims.clone();
        match mutation {
            "iss" => invalid.issuer = Some("https://evil.example".into()),
            "aud" => invalid = invalid.with_audience("other"),
            "exp" => invalid.expires_at = None,
            "sub" => invalid.subject = None,
            "empty-sub" => invalid.subject = Some("".into()),
            "nbf" => invalid.invalid_before = Some(attic_token::UnixTimeStamp::from_secs(u64::MAX / 2)),
            _ => unreachable!(),
        }
        assert!(external.verify(&key.sign(invalid).unwrap()).await.is_err(), "{mutation}");
    }
    let mut expired = claims.clone();
    expired.expires_at = Some(attic_token::UnixTimeStamp::from_secs(1));
    assert!(external.verify(&key.sign(expired).unwrap()).await.is_err());
    let wrong_key = RS256KeyPair::generate(2048).unwrap().with_key_id("test");
    assert!(external.verify(&wrong_key.sign(claims.clone()).unwrap()).await.is_err());
    let unknown_key = key.clone().with_key_id("unknown");
    let attempted = external.cache.lock().await.attempted;
    for _ in 0..3 {
        assert!(external.verify(&unknown_key.sign(claims.clone()).unwrap()).await.is_err());
    }
    assert_eq!(external.cache.lock().await.attempted, attempted);
    external.cache.lock().await.fetched = Some(Instant::now() - MAX_AGE);
    assert!(external.verify(&key.sign(claims).unwrap()).await.is_err());
}
