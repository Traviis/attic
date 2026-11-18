use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::config::upload_verification::PolicyHook;

#[derive(Debug, Deserialize)]
pub(crate) struct Decision {
    pub allow: bool,
    #[serde(default)]
    pub reason: String,
}

pub(crate) async fn evaluate(hook: &PolicyHook, input: &Value) -> Decision {
    let result = tokio::time::timeout(hook.timeout, invoke(hook, input)).await;
    match result {
        Ok(Ok(decision)) => decision,
        Ok(Err(error)) => Decision {
            allow: false,
            reason: error.to_string(),
        },
        Err(_) => Decision {
            allow: false,
            reason: "policy hook timed out".into(),
        },
    }
}

async fn invoke(hook: &PolicyHook, input: &Value) -> Result<Decision> {
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let bytes = if let Some(command) = &hook.command {
        let (program, args) = command
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty policy command"))?;
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let input = serde_json::to_vec(input)?;
        let write = async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        let read = async move {
            let mut bytes = Vec::new();
            stdout.take(65537).read_to_end(&mut bytes).await?;
            if bytes.len() > 65536 {
                bail!("policy hook output exceeds limit");
            }
            Ok::<_, anyhow::Error>(bytes)
        };
        let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
        let ((), bytes, status) = tokio::try_join!(write, read, wait)?;
        if !status.success() {
            bail!("policy hook exited unsuccessfully");
        }
        bytes
    } else {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let response = client
            .post(
                hook.url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("missing policy URL"))?,
            )
            .json(input)
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("policy hook HTTP status {}", response.status());
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > 65536 {
                bail!("policy hook output exceeds limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        bytes
    };
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_errors_and_invalid_responses_deny() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route(
                "/status",
                axum::routing::post(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
            )
            .route("/invalid", axum::routing::post(|| async { "not json" }))
            .route("/missing", axum::routing::post(|| async { "{}" }))
            .route(
                "/large",
                axum::routing::post(|| async { " ".repeat(65537) }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        for (path, reason) in [
            ("status", "503"),
            ("invalid", "expected"),
            ("missing", "missing field"),
            ("large", "exceeds limit"),
        ] {
            let hook = PolicyHook {
                command: None,
                url: Some(format!("http://{address}/{path}")),
                timeout: std::time::Duration::from_secs(2),
            };
            let decision = evaluate(&hook, &serde_json::json!({"version":1})).await;
            assert!(!decision.allow);
            assert!(decision.reason.contains(reason), "{}", decision.reason);
        }
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_decisions_fail_closed() {
        let mut hook = PolicyHook {
            command: Some(vec![
                "sh".into(),
                "-c".into(),
                "cat >/dev/null; printf '%s' '{\"allow\":true}'".into(),
            ]),
            url: None,
            timeout: std::time::Duration::from_secs(2),
        };
        let input = serde_json::json!({"version":1});
        assert!(evaluate(&hook, &input).await.allow);
        for (script, reason) in [
            (
                "cat >/dev/null; printf '%s' '{\"allow\":false,\"reason\":\"no host\"}'",
                "no host",
            ),
            ("cat >/dev/null; exit 1", "exited unsuccessfully"),
            ("cat >/dev/null; printf invalid", "expected value"),
            ("cat >/dev/null; printf '{}'", "missing field"),
        ] {
            hook.command.as_mut().unwrap()[2] = script.into();
            let decision = evaluate(&hook, &input).await;
            assert!(!decision.allow);
            assert!(decision.reason.contains(reason), "{}", decision.reason);
        }
        hook.command = Some(vec![
            "sh".into(),
            "-c".into(),
            "cat >/dev/null; head -c 65537 /dev/zero".into(),
        ]);
        let decision = evaluate(&hook, &input).await;
        assert!(!decision.allow);
        assert_eq!(decision.reason, "policy hook output exceeds limit");
        hook.command = Some(vec!["sleep".into(), "2".into()]);
        hook.timeout = std::time::Duration::from_millis(20);
        let decision = evaluate(&hook, &input).await;
        assert!(!decision.allow);
        assert_eq!(decision.reason, "policy hook timed out");
    }
}
