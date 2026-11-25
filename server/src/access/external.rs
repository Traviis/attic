//! Optional external identity JWT verification. No token-supplied URL is used.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use attic::cache::CacheNamePattern;
use attic_token::{CachePermission, JWTClaims, RS256PublicKey, Token};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jwt_simple::prelude::{RSAPublicKeyLike, VerificationOptions};
use reqwest::{Client, Url};
use serde::{Deserialize, Deserializer, de};
use serde_json::Value;
use tokio::sync::Mutex;

const REFRESH: Duration = Duration::from_secs(300);
const MAX_AGE: Duration = Duration::from_secs(600);
const RETRY: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 1024 * 1024;
const MAX_TOKEN: usize = 16 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExternalJwtConfig {
    pub issuer: String,
    pub audience: String,
    /// Explicit allowlist; only RS256 is supported.
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub mappings: Vec<PermissionMapping>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PermissionMapping {
    /// A top-level claim containing an array of strings (e.g. groups or roles).
    pub claim: String,
    pub value: String,
    pub caches: indexmap::IndexMap<CacheNamePattern, CachePermission>,
}

pub fn deserialize_config<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<ExternalJwtConfig>, D::Error> {
    let config = Option::<ExternalJwtConfig>::deserialize(deserializer)?;
    if let Some(config) = &config {
        config.validate().map_err(de::Error::custom)?;
    }
    Ok(config)
}

impl ExternalJwtConfig {
    fn validate(&self) -> Result<()> {
        trusted_url(&self.issuer)?;
        ensure!(
            !self.audience.trim().is_empty(),
            "external JWT audience is required"
        );
        ensure!(
            self.algorithms == ["RS256"],
            "external JWT algorithms must be [RS256]"
        );
        for mapping in &self.mappings {
            ensure!(
                !mapping.claim.is_empty() && !mapping.value.is_empty(),
                "empty external JWT mapping"
            );
            ensure!(
                !matches!(
                    mapping.claim.as_str(),
                    "iss"
                        | "sub"
                        | "aud"
                        | "exp"
                        | "nbf"
                        | "iat"
                        | "jti"
                        | "nonce"
                        | attic_token::CLAIM_NAMESPACE
                ),
                "mapping requires a group/role claim"
            );
        }
        Ok(())
    }

    fn map_claims(&self, claims: JWTClaims<Value>) -> Token {
        let mut token = Token::from_verified_external_claims(claims.clone());
        for mapping in &self.mappings {
            let Some(values) = claims.custom.get(&mapping.claim).and_then(Value::as_array) else {
                continue;
            };
            // A mixed-type claim is not a string array and never grants access.
            if values.iter().all(Value::is_string)
                && values
                    .iter()
                    .any(|value| value.as_str() == Some(&mapping.value))
            {
                for (pattern, permission) in &mapping.caches {
                    let grant = token.get_or_insert_permission_mut(pattern.clone());
                    grant.pull |= permission.pull;
                    grant.push |= permission.push;
                    grant.delete |= permission.delete;
                    grant.create_cache |= permission.create_cache;
                    grant.configure_cache |= permission.configure_cache;
                    grant.configure_cache_retention |= permission.configure_cache_retention;
                    grant.destroy_cache |= permission.destroy_cache;
                }
            }
        }
        token
    }
}

fn trusted_url(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.query().is_none(),
        "JWT URL must not contain userinfo, query or fragment"
    );
    let loopback = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "JWT URL must use HTTPS (literal loopback HTTP is test-only)"
    );
    ensure!(url.host().is_some(), "JWT URL requires host");
    Ok(url)
}

/// Shared per-server cache. Holding the lock across refresh coalesces all callers;
/// retry spacing is global, including failures and attacker-chosen unknown kids.
#[derive(Debug)]
pub struct ExternalJwt {
    config: ExternalJwtConfig,
    client: Client,
    cache: Mutex<KeyCache>,
}

#[derive(Debug, Default)]
struct KeyCache {
    keys: HashMap<String, RS256PublicKey>,
    fetched: Option<Instant>,
    attempted: Option<Instant>,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    n: Option<String>,
    e: Option<String>,
}

impl ExternalJwt {
    pub fn new(config: ExternalJwtConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            cache: Mutex::new(KeyCache::default()),
        })
    }

    /// Unverified payload is used only as a routing selector, never as authority.
    pub fn selects(&self, jwt: &str) -> bool {
        unverified_payload(jwt)
            .ok()
            .and_then(|claims| claims.get("iss").and_then(Value::as_str).map(str::to_owned))
            .as_deref()
            == Some(&self.config.issuer)
    }

    pub async fn refresh_if_due(&self) {
        let mut cache = self.cache.lock().await;
        if cache.fetched.is_none_or(|at| at.elapsed() >= REFRESH)
            && cache.attempted.is_none_or(|at| at.elapsed() >= RETRY)
            && let Err(error) = self.refresh(&mut cache).await
        {
            // Do not include response bodies or token material in diagnostics.
            tracing::warn!(%error, "External JWT key refresh failed");
        }
    }

    async fn json<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T> {
        let mut response = self.client.get(url).send().await?.error_for_status()?;
        ensure!(
            !response.status().is_redirection(),
            "JWT discovery/JWKS redirects are forbidden"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|len| len <= MAX_BODY as u64),
            "JWT response too large"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= MAX_BODY,
                "JWT response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn refresh(&self, cache: &mut KeyCache) -> Result<()> {
        ensure!(
            cache.attempted.is_none_or(|at| at.elapsed() >= RETRY),
            "JWT refresh rate limited"
        );
        cache.attempted = Some(Instant::now());
        let issuer = trusted_url(&self.config.issuer)?;
        let discovery_url = trusted_url(&format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        ))?;
        let discovery: Discovery = self.json(discovery_url).await?;
        ensure!(
            discovery.issuer == self.config.issuer,
            "discovery issuer mismatch"
        );
        let jwks_url = trusted_url(&discovery.jwks_uri)?;
        ensure!(
            jwks_url.origin() == issuer.origin(),
            "JWKS must share issuer origin"
        );
        let jwks: Jwks = self.json(jwks_url).await?;
        let keys = parse_keys(jwks)?;
        cache.keys = keys;
        cache.fetched = Some(Instant::now());
        Ok(())
    }

    pub async fn verify(&self, jwt: &str) -> Result<Token> {
        ensure!(jwt.len() <= MAX_TOKEN, "JWT too large");
        let header: Value = decode_part(jwt.split('.').next().context("missing header")?)?;
        ensure!(
            header.get("alg").and_then(Value::as_str) == Some("RS256"),
            "JWT algorithm not allowed"
        );
        ensure!(
            header.get("crit").is_none() && header.get("b64").is_none(),
            "unsupported JWT critical/encoding headers"
        );
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.is_empty())
            .context("JWT requires kid")?;
        let key = {
            let mut cache = self.cache.lock().await;
            let stale = cache.fetched.is_none_or(|at| at.elapsed() >= REFRESH);
            if stale || !cache.keys.contains_key(kid) {
                // Failed refresh never extends the age of previously trusted keys.
                let _ = self.refresh(&mut cache).await;
            }
            ensure!(
                cache.fetched.is_some_and(|at| at.elapsed() < MAX_AGE),
                "JWT keys unavailable or expired"
            );
            cache.keys.get(kid).context("unknown JWT kid")?.clone()
        };
        let options = VerificationOptions {
            allowed_issuers: Some(HashSet::from([self.config.issuer.clone()])),
            allowed_audiences: Some(HashSet::from([self.config.audience.clone()])),
            required_key_id: Some(kid.to_owned()),
            time_tolerance: Some(jwt_simple::prelude::Duration::from_secs(0)),
            max_token_length: Some(MAX_TOKEN),
            max_header_length: Some(4096),
            ..Default::default()
        };
        let claims: JWTClaims<Value> = key.verify_token(jwt, Some(options))?;
        ensure!(claims.expires_at.is_some(), "external JWT requires exp");
        ensure!(
            claims
                .subject
                .as_ref()
                .is_some_and(|sub| !sub.trim().is_empty()),
            "external JWT requires nonempty sub"
        );
        Ok(self.config.map_claims(claims))
    }
}

fn parse_keys(jwks: Jwks) -> Result<HashMap<String, RS256PublicKey>> {
    let mut keys = HashMap::new();
    for jwk in jwks.keys {
        if jwk.kty != "RSA" {
            continue;
        }
        let kid = jwk
            .kid
            .filter(|kid| !kid.is_empty())
            .context("RSA JWK requires kid")?;
        ensure!(
            jwk.alg.as_deref().is_none_or(|alg| alg == "RS256"),
            "incompatible RSA JWK alg"
        );
        ensure!(
            jwk.usage.as_deref().is_none_or(|usage| usage == "sig"),
            "incompatible RSA JWK use"
        );
        ensure!(
            jwk.key_ops.as_ref().is_none_or(|ops| ops == &["verify"]),
            "incompatible RSA JWK key_ops"
        );
        let n = URL_SAFE_NO_PAD.decode(jwk.n.context("RSA JWK requires n")?)?;
        let e = URL_SAFE_NO_PAD.decode(jwk.e.context("RSA JWK requires e")?)?;
        ensure!(
            (n.len() > 256 || (n.len() == 256 && n[0] >= 128)) && n.len() <= 1024,
            "RSA modulus must be 2048..8192 bits"
        );
        let key = RS256PublicKey::from_components(&n, &e)?;
        ensure!(keys.insert(kid, key).is_none(), "duplicate RSA JWK kid");
    }
    ensure!(!keys.is_empty(), "no supported JWT verification keys");
    Ok(keys)
}

fn decode_part(part: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part)?)?)
}

fn unverified_payload(jwt: &str) -> Result<Value> {
    if jwt.len() > MAX_TOKEN {
        bail!("JWT too large");
    }
    decode_part(jwt.split('.').nth(1).context("missing JWT payload")?)
}

#[cfg(test)]
mod tests;
