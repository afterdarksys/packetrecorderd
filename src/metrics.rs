use lazy_static::lazy_static;
use prometheus::{Counter, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Registry};
use std::sync::Once;

static REGISTER_METRICS: Once = Once::new();

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    
    // Packet counters
    pub static ref PACKETS_TOTAL: IntCounter = IntCounter::new(
        "packetrecorder_packets_total",
        "Total number of packets captured"
    ).unwrap();
    
    pub static ref BYTES_TOTAL: IntCounter = IntCounter::new(
        "packetrecorder_bytes_total",
        "Total bytes captured"
    ).unwrap();
    
    pub static ref PACKETS_DROPPED: IntCounter = IntCounter::new(
        "packetrecorder_packets_dropped_total",
        "Total packets dropped"
    ).unwrap();
    
    // Protocol counters
    pub static ref PROTOCOL_PACKETS: Counter = Counter::new(
        "packetrecorder_protocol_packets",
        "Packets by protocol"
    ).unwrap();
    
    // Active sessions
    pub static ref ACTIVE_SESSIONS: IntGauge = IntGauge::new(
        "packetrecorder_active_sessions",
        "Number of active capture sessions"
    ).unwrap();
    
    // Flow table size
    pub static ref FLOW_TABLE_SIZE: IntGauge = IntGauge::new(
        "packetrecorder_flow_table_size",
        "Number of flows in flow table"
    ).unwrap();
    
    // Processing time histogram
    pub static ref PACKET_PROCESSING_TIME: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "packetrecorder_packet_processing_seconds",
            "Time to process a packet"
        ).buckets(vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005])
    ).unwrap();
    
    // Database write time
    pub static ref DB_WRITE_TIME: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "packetrecorder_db_write_seconds",
            "Time to write to database"
        ).buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05])
    ).unwrap();
    pub static ref PLUGIN_INVOCATIONS: IntCounterVec = IntCounterVec::new(
        prometheus::Opts::new("packetrecorder_plugin_invocations_total", "Plugin decoder invocations"),
        &["plugin", "result"]
    ).unwrap();
    pub static ref PLUGIN_LATENCY: HistogramVec = HistogramVec::new(
        HistogramOpts::new("packetrecorder_plugin_latency_seconds", "Plugin decoder latency")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
        &["plugin"]
    ).unwrap();
}

pub fn register_metrics() {
  REGISTER_METRICS.call_once(|| {
    REGISTRY.register(Box::new(PACKETS_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(BYTES_TOTAL.clone())).unwrap();
    REGISTRY.register(Box::new(PACKETS_DROPPED.clone())).unwrap();
    REGISTRY.register(Box::new(ACTIVE_SESSIONS.clone())).unwrap();
    REGISTRY.register(Box::new(FLOW_TABLE_SIZE.clone())).unwrap();
    REGISTRY.register(Box::new(PACKET_PROCESSING_TIME.clone())).unwrap();
    REGISTRY.register(Box::new(DB_WRITE_TIME.clone())).unwrap();
    REGISTRY.register(Box::new(PLUGIN_INVOCATIONS.clone())).unwrap();
    REGISTRY.register(Box::new(PLUGIN_LATENCY.clone())).unwrap();
  });
}

pub fn metrics_text() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[cfg(test)]
mod tests {
    #[test]
    fn metric_registration_is_idempotent() {
        super::register_metrics();
        super::register_metrics();
    }
}
