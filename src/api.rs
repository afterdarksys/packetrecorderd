use axum::{
    extract::State,
    http::HeaderMap,
    http::StatusCode,
    response::IntoResponse,
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use crate::storage::PacketStore;
use crate::metrics;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Mutex<PacketStore>>,
    events: broadcast::Sender<ApiEvent>,
    api_keys: Arc<std::collections::HashSet<String>>,
}

#[derive(Clone, Serialize)]
pub struct ApiEvent {
    pub type_: String,
    pub ts_rfc3339: String,
}

impl ApiEvent {
    fn heartbeat() -> Self {
        Self {
            type_: "heartbeat".to_string(),
            ts_rfc3339: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn load_api_keys_from_env() -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();

    if let Ok(key) = std::env::var("PACKETRECORDER_API_KEY") {
        let k = key.trim();
        if !k.is_empty() {
            keys.insert(k.to_string());
        }
    }

    if let Ok(keys_env) = std::env::var("PACKETRECORDER_API_KEYS") {
        for k in keys_env.split(',') {
            let t = k.trim();
            if !t.is_empty() {
                keys.insert(t.to_string());
            }
        }
    }

    if let Ok(path) = std::env::var("PACKETRECORDER_API_KEYS_FILE") {
        if let Ok(contents) = std::fs::read_to_string(path) {
            for line in contents.lines() {
                let t = line.trim();
                if !t.is_empty() {
                    keys.insert(t.to_string());
                }
            }
        }
    }

    keys
}

fn authorized(headers: &HeaderMap, keys: &std::collections::HashSet<String>) -> bool {
    if keys.is_empty() {
        return true;
    }

    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return keys.contains(v.trim());
    }

    if let Some(v) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if let Some(rest) = v.strip_prefix("Bearer ") {
            return keys.contains(rest.trim());
        }
    }

    false
}

impl ApiState {
    pub fn new(store: Arc<Mutex<PacketStore>>) -> Self {
        let (tx, _) = broadcast::channel(1024);
        let keys = load_api_keys_from_env();
        Self {
            store,
            events: tx,
            api_keys: Arc::new(keys),
        }
    }

    pub fn emit(&self, evt: ApiEvent) {
        let _ = self.events.send(evt);
    }
}

// Response types
#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Serialize)]
pub struct StatsResponse {
    packets_total: u64,
    bytes_total: u64,
    active_sessions: i64,
    flow_table_size: i64,
}

#[derive(Serialize)]
pub struct SessionResponse {
    id: String,
    interface: String,
    filter: Option<String>,
    start_time: String,
    end_time: Option<String>,
    packet_count: i64,
}

// Handlers
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics::metrics_text(),
    )
}

async fn stats() -> Json<StatsResponse> {
    Json(StatsResponse {
        packets_total: metrics::PACKETS_TOTAL.get(),
        bytes_total: metrics::BYTES_TOTAL.get(),
        active_sessions: metrics::ACTIVE_SESSIONS.get(),
        flow_table_size: metrics::FLOW_TABLE_SIZE.get(),
    })
}

async fn list_sessions(State(state): State<ApiState>) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    let store = state.store.lock().unwrap();
    
    match store.list_sessions() {
        Ok(sessions) => {
            let response: Vec<SessionResponse> = sessions
                .into_iter()
                .map(|s| SessionResponse {
                    id: s.id,
                    interface: s.interface,
                    filter: s.filter,
                    start_time: s.start_time.to_rfc3339(),
                    end_time: s.end_time.map(|t| t.to_rfc3339()),
                    packet_count: s.packet_count,
                })
                .collect();
            Ok(Json(response))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn events(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if !authorized(&headers, &state.api_keys) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| {
        match msg {
            Ok(evt) => {
                let json = serde_json::to_string(&evt).ok()?;
                Some(Ok(Event::default().event("event").data(json)))
            }
            Err(_) => None,
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/sessions", get(list_sessions))
        .route("/api/v1/events", get(events))
        .with_state(state)
}

pub async fn serve(addr: std::net::SocketAddr, state: ApiState) {
    let heartbeat_tx = state.events.clone();
    let app = create_router(state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = heartbeat_tx.send(ApiEvent::heartbeat());
        }
    });
    
    tracing::info!("API server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
