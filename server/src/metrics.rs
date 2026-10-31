use std::sync::OnceLock;
use std::time::Duration;

use axum::http::StatusCode;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, UpDownCounter};

struct HttpMetrics {
    requests: Counter<u64>,
    active_requests: UpDownCounter<i64>,
    request_duration: Histogram<f64>,
}

struct OperationMetrics {
    operations: Counter<u64>,
    duration: Histogram<f64>,
    bytes: Counter<u64>,
}

pub struct ActiveHttpRequest {
    method: String,
    started_at: std::time::Instant,
    route: String,
}

impl Drop for ActiveHttpRequest {
    fn drop(&mut self) {
        // Balance the gauge even when a request is cancelled or panics.
        http_metrics().active_requests.add(
            -1,
            &[KeyValue::new("http.request.method", self.method.clone())],
        );
    }
}

impl ActiveHttpRequest {
    pub fn finish(self, status: StatusCode) {
        let metrics = http_metrics();
        let attributes = [
            KeyValue::new("http.request.method", self.method.clone()),
            KeyValue::new("http.response.status_code", i64::from(status.as_u16())),
            KeyValue::new("http.response.status_class", status_class(status)),
            KeyValue::new("http.route", self.route.clone()),
        ];
        metrics.requests.add(1, &attributes);
        metrics
            .request_duration
            .record(self.started_at.elapsed().as_secs_f64(), &attributes);
    }
}

pub fn start_http_request(method: &str, route: &str) -> ActiveHttpRequest {
    http_metrics().active_requests.add(
        1,
        &[KeyValue::new("http.request.method", method.to_owned())],
    );

    ActiveHttpRequest {
        method: method.to_owned(),
        started_at: std::time::Instant::now(),
        route: route.to_owned(),
    }
}

pub fn record_operation(name: &'static str, outcome: &'static str, duration: Duration) {
    let attributes = [
        KeyValue::new("operation.name", name),
        KeyValue::new("operation.outcome", outcome),
    ];
    let metrics = operation_metrics();
    metrics.operations.add(1, &attributes);
    metrics.duration.record(duration.as_secs_f64(), &attributes);
}

pub fn add_bytes(name: &'static str, bytes: u64, attributes: &[KeyValue]) {
    let mut all_attributes = Vec::with_capacity(attributes.len() + 1);
    all_attributes.push(KeyValue::new("operation.name", name));
    all_attributes.extend_from_slice(attributes);
    operation_metrics().bytes.add(bytes, &all_attributes);
}

pub fn add_count(name: &'static str, count: u64, attributes: &[KeyValue]) {
    let mut all_attributes = Vec::with_capacity(attributes.len() + 1);
    all_attributes.push(KeyValue::new("operation.name", name));
    all_attributes.extend_from_slice(attributes);
    operation_metrics().operations.add(count, &all_attributes);
}

fn http_metrics() -> &'static HttpMetrics {
    static METRICS: OnceLock<HttpMetrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let meter = global::meter("atticd.http");
        HttpMetrics {
            requests: meter
                .u64_counter("http.server.request.count")
                .with_description("HTTP requests received")
                .build(),
            active_requests: meter
                .i64_up_down_counter("http.server.active_requests")
                .with_description("HTTP requests currently being processed")
                .build(),
            request_duration: meter
                .f64_histogram("http.server.request.duration")
                .with_description("HTTP request duration until response headers")
                .with_unit("s")
                .with_boundaries(vec![
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
                ])
                .build(),
        }
    })
}

fn operation_metrics() -> &'static OperationMetrics {
    static METRICS: OnceLock<OperationMetrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let meter = global::meter("atticd.operations");
        OperationMetrics {
            operations: meter
                .u64_counter("attic.operation.count")
                .with_description("Attic operations and processed objects")
                .build(),
            duration: meter
                .f64_histogram("attic.operation.duration")
                .with_description("Attic operation duration")
                .with_unit("s")
                .with_boundaries(vec![
                    0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 900.0,
                ])
                .build(),
            bytes: meter
                .u64_counter("attic.operation.bytes")
                .with_description("Bytes processed by Attic operations")
                .with_unit("By")
                .build(),
        }
    })
}

pub(crate) fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::status_class;

    #[test]
    fn exports_route_and_upload_outcomes_and_balances_cancelled_handlers() {
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
        use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};

        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_periodic_exporter(exporter.clone())
            .build();
        opentelemetry::global::set_meter_provider(provider.clone());

        super::start_http_request("GET", "/{cache}/{path}").finish(StatusCode::NOT_FOUND);
        drop(super::start_http_request("GET", "unmatched"));
        super::add_count(
            "upload.objects",
            1,
            &[
                opentelemetry::KeyValue::new("upload.kind", "deduplicated"),
                opentelemetry::KeyValue::new("operation.outcome", "success"),
            ],
        );
        provider.force_flush().unwrap();
        let batches = exporter.get_finished_metrics().unwrap();
        let metrics: Vec<_> = batches
            .iter()
            .flat_map(|b| b.scope_metrics())
            .flat_map(|s| s.metrics())
            .collect();
        let active = metrics
            .iter()
            .find(|m| m.name() == "http.server.active_requests")
            .unwrap();
        let AggregatedMetrics::I64(MetricData::Sum(sum)) = active.data() else {
            panic!("expected sum")
        };
        assert!(sum.data_points().all(|p| p.value() == 0));
        let requests = metrics
            .iter()
            .find(|m| m.name() == "http.server.request.count")
            .unwrap();
        let AggregatedMetrics::U64(MetricData::Sum(sum)) = requests.data() else {
            panic!("expected sum")
        };
        let points: Vec<_> = sum.data_points().collect();
        assert_eq!(points.len(), 1); // cancelled request is not a completed response
        assert_eq!(points[0].value(), 1);
        assert!(
            points[0]
                .attributes()
                .any(|a| a.key.as_str() == "http.route" && a.value.as_str() == "/{cache}/{path}")
        );
        let operations = metrics
            .iter()
            .find(|m| m.name() == "attic.operation.count")
            .unwrap();
        let AggregatedMetrics::U64(MetricData::Sum(sum)) = operations.data() else {
            panic!("expected sum")
        };
        assert!(sum.data_points().any(|p| {
            p.value() == 1
                && p.attributes()
                    .any(|a| a.key.as_str() == "upload.kind" && a.value.as_str() == "deduplicated")
        }));
        provider.shutdown().unwrap();
    }

    #[test]
    fn groups_http_status_by_class() {
        assert_eq!(status_class(StatusCode::OK), "2xx");
        assert_eq!(status_class(StatusCode::NOT_FOUND), "4xx");
        assert_eq!(status_class(StatusCode::INTERNAL_SERVER_ERROR), "5xx");
    }
}
