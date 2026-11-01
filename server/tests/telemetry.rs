use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn exports_http_signals() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "emit_signals", "--nocapture"])
        .env("ATTIC_TELEMETRY_PROBE", "1")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
        .env("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
        .env("OTEL_SDK_DISABLED", "false")
        .env("OTEL_RESOURCE_ATTRIBUTES", "service.name=attic-export-test")
        .env_remove("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut signals = BTreeSet::new();
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break request.len();
                    }
                };
                let headers = String::from_utf8_lossy(&request);
                let path = headers
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                request.resize(header_end + length, 0);
                stream.read_exact(&mut request[header_end..]).unwrap();
                assert!(
                    request[header_end..]
                        .windows(b"attic-export-test".len())
                        .any(|w| w == b"attic-export-test")
                );
                signals.insert(path);
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("receiver failed: {error}"),
        }
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        signals,
        BTreeSet::from([
            "/v1/logs".to_owned(),
            "/v1/metrics".to_owned(),
            "/v1/traces".to_owned()
        ])
    );
}

#[test]
fn emit_signals() {
    if std::env::var_os("ATTIC_TELEMETRY_PROBE").is_none() {
        return;
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _entered = runtime.enter();
    let telemetry = attic_server::telemetry::init(false).unwrap();
    {
        let span = tracing::info_span!("export_probe");
        let _entered = span.enter();
        tracing::info!("export probe log");
        opentelemetry::global::meter("export_probe")
            .u64_counter("export_probe_count")
            .build()
            .add(1, &[]);
    }
    telemetry.shutdown().unwrap();
}
