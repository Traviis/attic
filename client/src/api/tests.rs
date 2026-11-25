use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

fn recording_server(requests: usize) -> (String, std::thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}/", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let mut headers = Vec::new();
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
                if bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            headers.push(String::from_utf8(bytes).unwrap());
            let body = r#"{"caches":[]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        }
        headers
    });
    (address, thread)
}

#[tokio::test]
async fn token_file_is_reread_per_request_and_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("token");
    std::fs::write(&path, "first\n").unwrap();
    let (endpoint, server) = recording_server(2);
    let client = ApiClient::from_server_config(ServerConfig {
        endpoint,
        upload_compression: true,
        token: Some(ServerTokenConfig::File {
            token_file: path.to_str().unwrap().into(),
        }),
    })
    .unwrap();
    client.list_caches().await.unwrap();
    let replacement = directory.path().join("replacement");
    std::fs::write(&replacement, "second\r\n").unwrap();
    std::fs::rename(replacement, &path).unwrap();
    client.list_caches().await.unwrap();
    let requests = server.join().unwrap();
    assert!(requests[0].contains("authorization: bearer first\r\n"));
    assert!(requests[1].contains("authorization: bearer second\r\n"));
    for invalid in ["", "\n", "one\ntwo", " space", "token\n\n"] {
        std::fs::write(&path, invalid).unwrap();
        let error = client.list_caches().await.unwrap_err();
        assert!(error.to_string().contains("Token file must contain"));
    }
    std::fs::write(&path, "x".repeat(16 * 1024 + 1)).unwrap();
    assert!(
        client
            .list_caches()
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds 16 KiB")
    );
    std::fs::remove_file(&path).unwrap();
    assert!(
        client
            .list_caches()
            .await
            .unwrap_err()
            .to_string()
            .contains("Failed to read token file")
    );
    std::fs::create_dir(&path).unwrap();
    assert!(
        client
            .list_caches()
            .await
            .unwrap_err()
            .to_string()
            .contains("Failed to read token file")
    );
}

#[tokio::test]
async fn inline_token_still_authenticates_requests() {
    let (endpoint, server) = recording_server(1);
    let client = ApiClient::from_server_config(ServerConfig {
        endpoint,
        upload_compression: true,
        token: Some(ServerTokenConfig::Raw {
            token: "inline-token".into(),
        }),
    })
    .unwrap();
    client.list_caches().await.unwrap();
    assert!(server.join().unwrap()[0].contains("authorization: bearer inline-token\r\n"));
}
