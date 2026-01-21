//! REST API for threat intelligence

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::models::{
    BulkImportRequest, BulkImportResponse, CreateIndicatorRequest, DashboardStats,
    Indicator, IndicatorFilter, IndicatorResponse, PaginatedResponse,
};
use crate::storage::ThreatIntelRepo;
use crate::enrichment::EnrichmentEngine;

/// Application state shared across handlers
pub struct AppState {
    pub repo: ThreatIntelRepo,
    pub enrichment: Arc<EnrichmentEngine>,
}

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))
        
        // Indicators
        .route("/api/v1/indicators", get(list_indicators))
        .route("/api/v1/indicators", post(create_indicator))
        .route("/api/v1/indicators/bulk", post(bulk_import))
        .route("/api/v1/indicators/:id", get(get_indicator))
        .route("/api/v1/indicators/:id", delete(delete_indicator))
        .route("/api/v1/indicators/:id/enrich", post(enrich_indicator))
        .route("/api/v1/indicators/:id/sightings", post(add_sighting))
        
        // Lookup (by value instead of ID)
        .route("/api/v1/lookup", get(lookup_indicator))
        .route("/api/v1/lookup/:value", get(lookup_indicator_by_path))
        
        // Statistics
        .route("/api/v1/stats", get(get_stats))
        
        // Sources/Feeds
        .route("/api/v1/sources", get(list_sources))
        .route("/api/v1/feeds/refresh", post(refresh_feeds))
        
        .with_state(state)
}

// ==================== Handlers ====================

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "sentinelforge",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_indicators(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<IndicatorFilter>,
) -> Result<Json<PaginatedResponse<Indicator>>, (StatusCode, Json<Value>)> {
    state
        .repo
        .search_indicators(&filter)
        .await
        .map(Json)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list indicators");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })
}

async fn create_indicator(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIndicatorRequest>,
) -> Result<(StatusCode, Json<Indicator>), (StatusCode, Json<Value>)> {
    let indicator = state
        .repo
        .upsert_indicator(&req, None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create indicator");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    // Trigger async enrichment
    let enrichment = state.enrichment.clone();
    let repo = state.repo.clone();
    let indicator_clone = indicator.clone();
    
    tokio::spawn(async move {
        let results = enrichment.enrich_all(&indicator_clone).await;
        for (enrichment_type, provider, data, ttl) in results {
            if let Err(e) = repo
                .add_enrichment(indicator_clone.id, &enrichment_type, &provider, data, Some(ttl))
                .await
            {
                tracing::warn!(error = %e, "Failed to save enrichment");
            }
        }
    });

    Ok((StatusCode::CREATED, Json(indicator)))
}

async fn bulk_import(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BulkImportRequest>,
) -> Result<Json<BulkImportResponse>, (StatusCode, Json<Value>)> {
    let total = req.indicators.len();
    let mut created = 0;
    let mut updated = 0;
    let mut failed = 0;
    let mut errors = vec![];

    for mut indicator_req in req.indicators {
        // Apply bulk defaults
        if indicator_req.source.is_none() {
            indicator_req.source = Some(req.source.clone());
        }
        if indicator_req.tlp.is_none() {
            indicator_req.tlp = req.tlp.clone();
        }
        if let Some(ref bulk_tags) = req.tags {
            let mut tags = indicator_req.tags.unwrap_or_default();
            tags.extend(bulk_tags.clone());
            indicator_req.tags = Some(tags);
        }

        match state.repo.upsert_indicator(&indicator_req, None).await {
            Ok(_) => created += 1,
            Err(e) => {
                failed += 1;
                errors.push(format!("{}: {}", indicator_req.value, e));
            }
        }
    }

    Ok(Json(BulkImportResponse {
        total,
        created,
        updated,
        failed,
        errors,
    }))
}

async fn get_indicator(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<IndicatorResponse>, (StatusCode, Json<Value>)> {
    let indicator = state
        .repo
        .get_indicator(id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Indicator not found" })),
            )
        })?;

    let enrichments = state.repo.get_enrichments(id).await.unwrap_or_default();
    let sightings_count = state.repo.count_sightings(id).await.unwrap_or(0);

    Ok(Json(IndicatorResponse {
        indicator,
        enrichments,
        sightings_count,
        related_indicators: vec![], // TODO: implement related lookup
    }))
}

async fn delete_indicator(
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<Uuid>,
) -> StatusCode {
    // TODO: implement delete
    StatusCode::NO_CONTENT
}

async fn enrich_indicator(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let indicator = state
        .repo
        .get_indicator(id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Indicator not found" })),
            )
        })?;

    let results = state.enrichment.enrich_all(&indicator).await;
    let mut enrichments_added = 0;

    for (enrichment_type, provider, data, ttl) in results {
        if let Ok(_) = state
            .repo
            .add_enrichment(id, &enrichment_type, &provider, data, Some(ttl))
            .await
        {
            enrichments_added += 1;
        }
    }

    Ok(Json(json!({
        "message": "Enrichment complete",
        "enrichments_added": enrichments_added,
    })))
}

async fn add_sighting(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let source = body
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("manual");

    let context = body.get("context").cloned();

    let sighting = state
        .repo
        .add_sighting(id, source, context)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    Ok(Json(json!({
        "id": sighting.id,
        "observed_at": sighting.observed_at,
    })))
}

async fn lookup_indicator(
    State(state): State<Arc<AppState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let value = params.get("value").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing 'value' parameter" })),
        )
    })?;

    lookup_by_value(&state, value).await
}

async fn lookup_indicator_by_path(
    State(state): State<Arc<AppState>>,
    Path(value): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    lookup_by_value(&state, &value).await
}

async fn lookup_by_value(
    state: &Arc<AppState>,
    value: &str,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let indicator = state
        .repo
        .get_indicator_by_value(value)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    match indicator {
        Some(ind) => {
            let enrichments = state.repo.get_enrichments(ind.id).await.unwrap_or_default();
            Ok(Json(json!({
                "found": true,
                "indicator": ind,
                "enrichments": enrichments,
            })))
        }
        None => Ok(Json(json!({
            "found": false,
            "value": value,
        }))),
    }
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DashboardStats>, (StatusCode, Json<Value>)> {
    state
        .repo
        .get_stats()
        .await
        .map(Json)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })
}

async fn list_sources(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sources = state
        .repo
        .get_enabled_sources()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        })?;

    Ok(Json(json!({ "sources": sources })))
}

async fn refresh_feeds(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // TODO: trigger feed refresh job
    Ok(Json(json!({
        "message": "Feed refresh triggered",
    })))
}
