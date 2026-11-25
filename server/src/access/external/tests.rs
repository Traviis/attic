use super::*;
use attic::cache::CacheName;
use jwt_simple::prelude::{Claims, RS256KeyPair, RSAKeyPairLike};
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
    let claims = Claims::with_custom_claims(
        json!({
            "groups":["readers"], "roles":["writers"],
            attic_token::CLAIM_NAMESPACE: {"caches":{"*":{"cd":1}}}
        }),
        jwt_simple::prelude::Duration::from_secs(60),
    )
    .with_issuer("https://identity.example/attic")
    .with_subject("alice");
    let token = config().map_claims(claims);
    let permission = token.get_permission_for_cache(&CacheName::new("team-ci-one".into()).unwrap());
    assert!(permission.pull && permission.push); // same pattern grants merged
    assert!(!permission.create_cache); // first wildcard match, not union
    let permission =
        token.get_permission_for_cache(&CacheName::new("team-special".into()).unwrap());
    assert!(permission.delete && !permission.pull); // exact overrides wildcard
    assert!(
        !token
            .get_permission_for_cache(&CacheName::new("other".into()).unwrap())
            .destroy_cache
    );
    assert_eq!(token.sub(), Some("alice"));
    assert_eq!(
        token.principal(),
        Some("[\"https://identity.example/attic\",\"alice\"]")
    );
    let opaque = serde_json::to_value(token.opaque_claims()).unwrap();
    assert_eq!(opaque["iss"], "https://identity.example/attic");
    assert_eq!(opaque["sub"], "alice");
}

#[test]
fn malformed_group_claim_never_grants_permissions() {
    for groups in [json!("readers"), json!(["readers", 1]), json!(null)] {
        let claims = Claims::with_custom_claims(
            json!({"groups":groups}),
            jwt_simple::prelude::Duration::from_secs(60),
        );
        let token = config().map_claims(claims);
        assert!(
            !token
                .get_permission_for_cache(&CacheName::new("team-one".into()).unwrap())
                .can_discover()
        );
    }
}

#[test]
fn rejects_unsafe_configuration_urls() {
    for url in [
        "http://localhost:8200",
        "http://identity.example",
        "https://user:pass@identity.example",
        "https://identity.example/#fragment",
        "https://identity.example/?q=1",
        "file:///etc/passwd",
    ] {
        assert!(trusted_url(url).is_err(), "{url}");
    }
    for url in [
        "http://127.0.0.1:8200/v1/identity/oidc/provider/attic",
        "http://[::1]:8200",
        "https://identity.example/oidc",
    ] {
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
    assert!(
        parse_keys(serde_json::from_value(json!({"keys":[jwk.clone(),jwk.clone()]})).unwrap())
            .is_err()
    );
    for (field, value) in [
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
    ] {
        let mut incompatible = jwk.clone();
        incompatible[field] = value;
        assert!(
            parse_keys(serde_json::from_value(json!({"keys":[incompatible]})).unwrap()).is_err()
        );
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
    let claims = Claims::with_custom_claims(
        json!({"groups":["readers"]}),
        jwt_simple::prelude::Duration::from_secs(60),
    )
    .with_issuer(&external.config.issuer)
    .with_audience("attic")
    .with_subject("alice");
    assert!(
        external
            .verify(&key.sign(claims.clone()).unwrap())
            .await
            .is_ok()
    );
    for mutation in ["iss", "aud", "missing-iss", "missing-aud", "exp", "sub", "empty-sub", "nbf"] {
        let mut invalid = claims.clone();
        match mutation {
            "iss" => invalid.issuer = Some("https://evil.example".into()),
            "aud" => invalid = invalid.with_audience("other"),
            "missing-iss" => invalid.issuer = None,
            "missing-aud" => invalid.audiences = None,
            "exp" => invalid.expires_at = None,
            "sub" => invalid.subject = None,
            "empty-sub" => invalid.subject = Some("".into()),
            "nbf" => {
                invalid.invalid_before = Some(attic_token::UnixTimeStamp::from_secs(u64::MAX / 2))
            }
            _ => unreachable!(),
        }
        assert!(
            external.verify(&key.sign(invalid).unwrap()).await.is_err(),
            "{mutation}"
        );
    }
    let mut without_nbf = claims.clone();
    without_nbf.invalid_before = None;
    assert!(external.verify(&key.sign(without_nbf).unwrap()).await.is_ok());
    let mut expired = claims.clone();
    expired.expires_at = Some(attic_token::UnixTimeStamp::from_secs(1));
    assert!(external.verify(&key.sign(expired).unwrap()).await.is_err());
    let wrong_key = RS256KeyPair::generate(2048).unwrap().with_key_id("test");
    assert!(
        external
            .verify(&wrong_key.sign(claims.clone()).unwrap())
            .await
            .is_err()
    );
    let unknown_key = key.clone().with_key_id("unknown");
    let attempted = external.cache.lock().await.attempted;
    for _ in 0..3 {
        assert!(
            external
                .verify(&unknown_key.sign(claims.clone()).unwrap())
                .await
                .is_err()
        );
    }
    assert_eq!(external.cache.lock().await.attempted, attempted);
    external.cache.lock().await.fetched = Some(Instant::now() - MAX_AGE);
    assert!(external.verify(&key.sign(claims).unwrap()).await.is_err());
}

#[tokio::test]
async fn routing_never_falls_back_to_static_grants_for_external_issuer() {
    use crate::access::http::authenticate;
    let temp = tempfile::tempdir().unwrap();
    let template = include_str!("../../config-template.toml")
        .replace("%database_url%", "sqlite::memory:")
        .replace("%storage_path%", temp.path().to_str().unwrap())
        .replace(
            "token-rs256-secret-base64 = \"%token_rs256_secret_base64%\"",
            "token-hs256-secret-base64 = \"dGVzdA==\"",
        );
    let mut server_config: crate::config::Config = toml::from_str(&template).unwrap();
    server_config.jwt.external = Some(config());
    // Construct without startup network work; key cache below is authoritative.
    let external = ExternalJwt::new(config()).unwrap();
    let key = RS256KeyPair::generate(2048).unwrap().with_key_id("one");
    {
        let mut cache = external.cache.lock().await;
        cache.keys.insert("one".into(), key.public_key());
        cache.fetched = Some(Instant::now());
        cache.attempted = Some(Instant::now());
    }
    let state = std::sync::Arc::new(crate::StateInner {
        registry: tokio::sync::Mutex::new(crate::registry::Registry::new(
            server_config.upload_verification.clone(),
        )),
        config: server_config,
        external_jwt: Some(external),
        database: tokio::sync::OnceCell::new(),
        storage: tokio::sync::OnceCell::new(),
        access_tracker: tokio::sync::OnceCell::new(),
    });
    let mut static_token = Token::new(
        "static".into(),
        &(chrono::Utc::now() + chrono::Duration::hours(1)),
    );
    static_token
        .get_or_insert_permission_mut("*".parse().unwrap())
        .destroy_cache = true;
    let signature = state.config.jwt.signing_config.clone().into();
    let jwt = static_token.encode(&signature, &None, &None).unwrap();
    let verified = authenticate(&state, &jwt).await.unwrap();
    assert_eq!(verified.principal(), Some("static"));
    let pretending_external = static_token
        .encode(&signature, &Some(config().issuer), &None)
        .unwrap();
    assert!(authenticate(&state, &pretending_external).await.is_none());
    let claims = Claims::with_custom_claims(
        json!({attic_token::CLAIM_NAMESPACE:{"caches":{"*":{"cd":1}}}}),
        jwt_simple::prelude::Duration::from_secs(60),
    )
    .with_issuer(config().issuer)
    .with_audience("attic")
    .with_subject("alice");
    let verified = authenticate(&state, &key.sign(claims).unwrap())
        .await
        .unwrap();
    assert!(
        !verified
            .get_permission_for_cache(&CacheName::new("team-one".into()).unwrap())
            .can_discover()
    );
    assert_ne!(verified.principal(), Some("alice"));
}

#[tokio::test]
async fn unknown_kid_refresh_is_single_flight_and_never_uses_token_urls() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let key = RS256KeyPair::generate(2048).unwrap().with_key_id("rotated");
    let public = key.public_key().to_components();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route("/.well-known/openid-configuration", axum::routing::get({
            let issuer = issuer.clone(); let requests = requests.clone();
            move || { let issuer = issuer.clone(); let requests = requests.clone(); async move {
                requests.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"issuer":issuer, "jwks_uri":format!("{issuer}/keys")}))
            }}
        }))
        .route("/keys", axum::routing::get({
            let requests = requests.clone();
            move || { let requests = requests.clone(); let n = public.n.clone(); let e = public.e.clone(); async move {
                requests.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"keys":[{"kty":"RSA", "kid":"rotated", "n":URL_SAFE_NO_PAD.encode(n), "e":URL_SAFE_NO_PAD.encode(e)}]}))
            }}
        }));
    let app = app.fallback({
        let requests = requests.clone();
        move || { let requests = requests.clone(); async move {
            requests.fetch_add(1000, Ordering::SeqCst);
            axum::http::StatusCode::NOT_FOUND
        }}
    });
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut config = config();
    config.issuer = issuer.clone();
    let external = Arc::new(ExternalJwt::new(config).unwrap());
    let claims =
        Claims::with_custom_claims(json!({}), jwt_simple::prelude::Duration::from_secs(60))
            .with_issuer(&issuer)
            .with_audience("attic")
            .with_subject("alice");
    // Inject an attacker URL into a signed header; it must never be fetched.
    let mut parts: Vec<String> = key
        .sign(claims.clone())
        .unwrap()
        .split('.')
        .map(str::to_owned)
        .collect();
    let mut header = decode_part(&parts[0]).unwrap();
    header["jku"] = json!(format!("{issuer}/attacker"));
    parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    assert!(external.verify(&parts.join(".")).await.is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    // Age only the attempt, then force concurrent misses. One discovery/JWKS
    // pair is shared; all other waiters see the globally rate-limited attempt.
    external.cache.lock().await.attempted = Some(Instant::now() - RETRY);
    let jwt = key.with_key_id("unknown").sign(claims).unwrap();
    let mut tasks = Vec::new();
    for _ in 0..20 {
        let external = external.clone();
        let jwt = jwt.clone();
        tasks.push(tokio::spawn(
            async move { external.verify(&jwt).await.is_err() },
        ));
    }
    for task in tasks {
        assert!(task.await.unwrap());
    }
    assert_eq!(requests.load(Ordering::SeqCst), 4);
    server.abort();
}
