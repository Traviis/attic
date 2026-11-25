use anyhow::Result;
use clap::Parser;

use crate::cache::ServerName;
use crate::cli::Opts;
use crate::config::{Config, ServerConfig, ServerTokenConfig};

/// Log into an Attic server.
#[derive(Debug, Parser)]
pub struct Login {
    /// Name of the server.
    name: ServerName,

    /// Endpoint of the server.
    endpoint: String,

    /// Access token.
    #[clap(conflicts_with = "token_file")]
    token: Option<String>,

    /// Read the access token from this file for every request (e.g. Vault Agent).
    #[clap(long, conflicts_with = "token")]
    token_file: Option<String>,

    /// Set the server as the default.
    #[clap(long)]
    set_default: bool,
}

pub async fn run(opts: Opts) -> Result<()> {
    let sub = opts.command.as_login().unwrap();
    let mut config = Config::load()?;
    let mut config_m = config.as_mut();

    let source = sub
        .token_file
        .as_ref()
        .map(|path| ServerTokenConfig::File {
            token_file: path.clone(),
        })
        .or_else(|| {
            sub.token.as_ref().map(|token| ServerTokenConfig::Raw {
                token: token.clone(),
            })
        });
    // Check the explicitly selected source without persisting its contents.
    if let Some(source) = &source {
        source.get()?;
    }

    if let Some(server) = config_m.servers.get_mut(&sub.name) {
        eprintln!("✍️ Overwriting server \"{}\"", sub.name.as_str());

        server.endpoint = sub.endpoint.to_owned();

        if let Some(source) = source {
            server.token = Some(source);
        }
    } else {
        eprintln!("✍️ Configuring server \"{}\"", sub.name.as_str());

        config_m.servers.insert(
            sub.name.to_owned(),
            ServerConfig {
                endpoint: sub.endpoint.to_owned(),
                upload_compression: true,
                token: source,
            },
        );
    }

    if sub.set_default || config_m.servers.len() == 1 {
        config_m.default_server = Some(sub.name.to_owned());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_supports_explicit_exclusive_sources() {
        let inline =
            Login::try_parse_from(["login", "local", "http://localhost", "supplied-token"])
                .unwrap();
        assert_eq!(inline.token.as_deref(), Some("supplied-token"));
        let file = Login::try_parse_from([
            "login",
            "local",
            "http://localhost",
            "--token-file",
            "/run/token",
        ])
        .unwrap();
        assert_eq!(file.token_file.as_deref(), Some("/run/token"));
        assert!(
            Login::try_parse_from([
                "login",
                "local",
                "http://localhost",
                "inline",
                "--token-file",
                "/run/token"
            ])
            .is_err()
        );
    }
}
