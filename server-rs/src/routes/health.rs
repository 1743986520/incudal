use axum::Json;
use serde_json::json;

/// GET /api/health -> { status: 'ok', timestamp: <ISO> } (app.ts parity).
pub async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    }))
}
