//! Structured, asynchronous upload decision export.

use std::sync::{OnceLock, RwLock};

use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::{Resource, error::OTelSdkResult};

static LOGGER: OnceLock<RwLock<Option<SdkLogger>>> = OnceLock::new();

pub(crate) fn install(provider: &SdkLoggerProvider) {
    if let Ok(mut logger) = LOGGER.get_or_init(|| RwLock::new(None)).write() {
        *logger = Some(provider.logger("attic.audit"));
    }
}

pub(crate) fn configured() -> bool {
    LOGGER
        .get()
        .and_then(|logger| logger.read().ok())
        .is_some_and(|logger| logger.is_some())
}

pub(crate) fn emit(fields: &serde_json::Value) {
    if let Some(logger) = LOGGER.get().and_then(|logger| logger.read().ok())
        && let Some(logger) = logger.as_ref()
    {
        emit_record(logger, fields);
    } else {
        tracing::warn!(target: "attic.audit.fallback", audit = %fields, "Audit exporter unavailable");
    }
}

fn emit_record(logger: &SdkLogger, fields: &serde_json::Value) {
    let mut record = logger.create_log_record();
    record.set_severity_number(Severity::Info);
    record.set_body(AnyValue::String("Upload decision".into()));
    if let Some(fields) = fields.as_object() {
        for (key, value) in fields {
            let value = match value {
                serde_json::Value::Bool(value) => AnyValue::Boolean(*value),
                serde_json::Value::Number(value) => value
                    .as_i64()
                    .map(AnyValue::Int)
                    .unwrap_or_else(|| AnyValue::Double(value.as_f64().unwrap_or_default())),
                serde_json::Value::String(value) => AnyValue::String(value.clone().into()),
                serde_json::Value::Null => continue,
                value => AnyValue::String(value.to_string().into()),
            };
            record.add_attribute(key.clone(), value);
        }
    }
    logger.emit(record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::logs::InMemoryLogExporter;

    #[derive(Clone)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Unavailable;

    impl LogExporter for Unavailable {
        async fn export(&self, _: LogBatch<'_>) -> OTelSdkResult {
            Err(opentelemetry_sdk::error::OTelSdkError::InternalFailure(
                "offline".into(),
            ))
        }
    }

    #[tokio::test]
    async fn exporter_failure_warns_with_audit_fields() {
        let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        emit_record(
            &provider.logger("attic.audit"),
            &serde_json::json!({"event":"upload.accepted", "token.sub":"alice"}),
        );
        let logs = exporter.get_emitted_logs().unwrap();
        let batch = [(&logs[0].record, &logs[0].instrumentation)];
        assert!(
            Exporter(Unavailable)
                .export(LogBatch::new(&batch))
                .await
                .is_err()
        );
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains("WARN"));
        assert!(output.contains("upload.accepted"));
        assert!(output.contains("alice"));
        assert!(output.contains("offline"));
        provider.shutdown().unwrap();
    }

    #[derive(Debug)]
    struct Paused {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl LogExporter for Paused {
        async fn export(&self, _: LogBatch<'_>) -> OTelSdkResult {
            let _ = self.entered.send(());
            self.release.lock().unwrap().recv().unwrap();
            Ok(())
        }
    }

    #[test]
    fn saturated_queue_warns_without_waiting_for_exporter() {
        let bytes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let resource = Resource::builder_empty().build();
        let processor = Processor::new(
            Paused {
                entered: entered_tx,
                release: std::sync::Mutex::new(release_rx),
            },
            &resource,
            1,
        );
        let provider = SdkLoggerProvider::builder()
            .with_log_processor(processor)
            .build();
        let logger = provider.logger("attic.audit");
        emit_record(
            &logger,
            &serde_json::json!({"event":"upload.accepted","store_path":"first"}),
        );
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        emit_record(
            &logger,
            &serde_json::json!({"event":"upload.accepted","store_path":"queued"}),
        );
        emit_record(
            &logger,
            &serde_json::json!({"event":"upload.rejected","store_path":"overflow"}),
        );
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(output.contains("WARN"));
        assert!(output.contains("overflow"));
        assert!(output.contains("upload.rejected"));
        release_tx.send(()).unwrap();
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        release_tx.send(()).unwrap();
        provider.force_flush().unwrap();
        provider.shutdown().unwrap();
    }

    #[test]
    fn exports_named_audit_with_typed_attributes() {
        let exporter = InMemoryLogExporter::default();
        let provider = SdkLoggerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let logger = provider.logger("attic.audit");
        let fields = serde_json::json!({
            "event": "upload.rejected", "outcome": "rejected", "reason": "identity mismatch",
            "cache": "private", "store_path": "/nix/store/example", "nar_hash": "sha256:abc",
            "nar_size": 3, "deduplicated": true, "token.sub": "alice", "token.jti": "request-1",
            "client.address": "127.0.0.1:1234", "signatures.valid_count": 1, "min-signatures": 1,
            "signatures": [{"key_name":"host","status":"valid","metadata":{"identity":"bob"},"identity_mismatch":true}],
            "policy_hook.decision": "not_configured", "policy_hook.reason": "",
        });
        emit_record(&logger, &fields);
        let logs = exporter.get_emitted_logs().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].instrumentation.name(), "attic.audit");
        let attributes: std::collections::BTreeMap<_, _> = logs[0]
            .record
            .attributes_iter()
            .map(|(key, value)| (key.as_str(), value.clone()))
            .collect();
        assert_eq!(attributes["nar_size"], AnyValue::Int(3));
        assert_eq!(attributes["deduplicated"], AnyValue::Boolean(true));
        assert_eq!(attributes["token.sub"], AnyValue::String("alice".into()));
        assert_eq!(
            attributes["signatures"],
            AnyValue::String(fields["signatures"].to_string().into())
        );
        assert_eq!(attributes.len(), fields.as_object().unwrap().len());
        provider.shutdown().unwrap();
    }
}

#[derive(Debug)]
enum Message {
    Record(
        Box<(
            opentelemetry_sdk::logs::SdkLogRecord,
            opentelemetry::InstrumentationScope,
        )>,
    ),
    Flush(std::sync::mpsc::Sender<()>),
    Shutdown(std::sync::mpsc::Sender<OTelSdkResult>),
}

#[derive(Debug)]
pub(crate) struct Processor {
    sender: std::sync::mpsc::SyncSender<Message>,
}

impl Processor {
    pub(crate) fn new<E: LogExporter + 'static>(
        mut exporter: E,
        resource: &Resource,
        capacity: usize,
    ) -> Self {
        exporter.set_resource(resource);
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        std::thread::spawn(move || {
            while let Ok(message) = receiver.recv() {
                match message {
                    Message::Record(record) => {
                        let batch = [(&record.0, &record.1)];
                        let _ = futures::executor::block_on(exporter.export(LogBatch::new(&batch)));
                    }
                    Message::Flush(done) => {
                        let _ = done.send(());
                    }
                    Message::Shutdown(done) => {
                        let _ = done.send(exporter.shutdown());
                        break;
                    }
                }
            }
        });
        Self { sender }
    }
}

impl opentelemetry_sdk::logs::LogProcessor for Processor {
    fn emit(
        &self,
        record: &mut opentelemetry_sdk::logs::SdkLogRecord,
        scope: &opentelemetry::InstrumentationScope,
    ) {
        if self
            .sender
            .try_send(Message::Record(Box::new((record.clone(), scope.clone()))))
            .is_err()
            && scope.name() == "attic.audit"
        {
            tracing::warn!(target: "attic.audit.fallback", audit = ?record, "Audit export queue unavailable");
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.sender
            .try_send(Message::Flush(sender))
            .map_err(|e| opentelemetry_sdk::error::OTelSdkError::InternalFailure(e.to_string()))?;
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|e| opentelemetry_sdk::error::OTelSdkError::InternalFailure(e.to_string()))
    }

    fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> OTelSdkResult {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.sender
            .try_send(Message::Shutdown(sender))
            .map_err(|e| opentelemetry_sdk::error::OTelSdkError::InternalFailure(e.to_string()))?;
        receiver
            .recv_timeout(timeout)
            .map_err(|e| opentelemetry_sdk::error::OTelSdkError::InternalFailure(e.to_string()))?
    }
}

#[derive(Debug)]
pub(crate) struct Exporter<E>(pub E);

impl<E: LogExporter> LogExporter for Exporter<E> {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let fallback: Vec<_> = batch
            .iter()
            .filter(|(_, scope)| scope.name() == "attic.audit")
            .map(|(record, _)| format!("{:?}", record))
            .collect();
        let result = self.0.export(batch).await;
        if let Err(error) = &result {
            for record in fallback {
                tracing::warn!(target: "attic.audit.fallback", audit = %record, %error, "Audit export failed");
            }
        }
        result
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.0.set_resource(resource);
    }

    fn shutdown_with_timeout(&self, timeout: std::time::Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }
}
