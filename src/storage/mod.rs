//! Database storage layer for threat intelligence

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use crate::models::ioc_utils::{detect_ioc_type, normalize_ioc};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{
    CreateIndicatorRequest, DashboardStats, Enrichment, Indicator, IndicatorFilter,
    IocSource, IocType, PaginatedResponse, Severity, Sighting, Tlp,
};
// use crate::models::ioc_utils::{detect_ioc_type, normalize_ioc};

/// Database repository for threat intelligence
#[derive(Clone)]
pub struct ThreatIntelRepo {
    pool: PgPool,
}

impl ThreatIntelRepo {
    /// Create new repository with database connection
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await
            .context("Failed to connect to database")?;

        Ok(Self { pool })
    }

    /// Get the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run database migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run migrations")?;
        Ok(())
    }

    // ==================== Indicators ====================

    /// Create or update an indicator
    pub async fn upsert_indicator(&self, req: &CreateIndicatorRequest, source_id: Option<Uuid>) -> Result<Indicator> {
        let ioc_type = req.ioc_type.clone().or_else(|| detect_ioc_type(&req.value))
            .ok_or_else(|| anyhow::anyhow!("Could not detect IOC type for: {}", req.value))?;
        
        let normalized_value = normalize_ioc(&req.value, &ioc_type);
        let now = Utc::now();
        let expiration = req.expiration_days.map(|days| now + Duration::days(days as i64));
        
        let indicator = sqlx::query_as::<_, Indicator>(
            r#"
            INSERT INTO indicators (
                id, ioc_type, value, severity, confidence, threat_score, tlp,
                first_seen, last_seen, expiration, tags, source_ids, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9, $10, $11, $8, $8)
            ON CONFLICT (ioc_type, value) DO UPDATE SET
                severity = CASE WHEN EXCLUDED.severity > indicators.severity THEN EXCLUDED.severity ELSE indicators.severity END,
                confidence = GREATEST(indicators.confidence, EXCLUDED.confidence),
                last_seen = EXCLUDED.last_seen,
                tags = array_cat(indicators.tags, EXCLUDED.tags),
                source_ids = array_cat(indicators.source_ids, EXCLUDED.source_ids),
                updated_at = EXCLUDED.updated_at
            RETURNING *
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&ioc_type)
        .bind(&normalized_value)
        .bind(req.severity.clone().unwrap_or(Severity::Unknown))
        .bind(req.confidence.unwrap_or(50))
        .bind(req.confidence.unwrap_or(50)) // Initial threat_score = confidence
        .bind(req.tlp.clone().unwrap_or(Tlp::Amber))
        .bind(now)
        .bind(expiration)
        .bind(&req.tags.clone().unwrap_or_default())
        .bind(&source_id.map(|id| vec![id]).unwrap_or_default())
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert indicator")?;

        Ok(indicator)
    }

    /// Get indicator by ID
    pub async fn get_indicator(&self, id: Uuid) -> Result<Option<Indicator>> {
        let indicator = sqlx::query_as::<_, Indicator>(
            "SELECT * FROM indicators WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch indicator")?;

        Ok(indicator)
    }

    /// Get indicator by value
    pub async fn get_indicator_by_value(&self, value: &str) -> Result<Option<Indicator>> {
        // Try to detect type and normalize
        if let Some(ioc_type) = detect_ioc_type(value) {
            let normalized = normalize_ioc(value, &ioc_type);
            let indicator = sqlx::query_as::<_, Indicator>(
                "SELECT * FROM indicators WHERE ioc_type = $1 AND value = $2"
            )
            .bind(&ioc_type)
            .bind(&normalized)
            .fetch_optional(&self.pool)
            .await
            .context("Failed to fetch indicator by value")?;

            return Ok(indicator);
        }

        // Fallback to direct search
        let indicator = sqlx::query_as::<_, Indicator>(
            "SELECT * FROM indicators WHERE value = $1"
        )
        .bind(value)
        .fetch_optional(&self.pool)
        .await
        .context("Failed to fetch indicator by value")?;

        Ok(indicator)
    }

    /// Search indicators with filters
    pub async fn search_indicators(&self, filter: &IndicatorFilter) -> Result<PaginatedResponse<Indicator>> {
        let page = filter.page.unwrap_or(1).max(1);
        let per_page = filter.per_page.unwrap_or(50).min(1000);
        let offset = (page - 1) * per_page;

        // Build dynamic query
        let mut conditions = vec!["1=1".to_string()];
        
        if filter.ioc_type.is_some() {
            conditions.push("ioc_type = $1".to_string());
        }
        if filter.severity.is_some() {
            conditions.push("severity = $2".to_string());
        }
        if filter.min_confidence.is_some() {
            conditions.push("confidence >= $3".to_string());
        }
        if filter.min_threat_score.is_some() {
            conditions.push("threat_score >= $4".to_string());
        }
        if filter.search.is_some() {
            conditions.push("value ILIKE $5".to_string());
        }

        let where_clause = conditions.join(" AND ");

        // For simplicity, using a basic query - in production, use query builder
        let indicators = sqlx::query_as::<_, Indicator>(
            &format!(
                "SELECT * FROM indicators WHERE {} ORDER BY last_seen DESC LIMIT {} OFFSET {}",
                where_clause, per_page, offset
            )
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to search indicators")?;

        let total: (i64,) = sqlx::query_as(
            &format!("SELECT COUNT(*) FROM indicators WHERE {}", where_clause)
        )
        .fetch_one(&self.pool)
        .await
        .context("Failed to count indicators")?;

        Ok(PaginatedResponse {
            data: indicators,
            total: total.0,
            page,
            per_page,
            total_pages: (total.0 as f64 / per_page as f64).ceil() as i64,
        })
    }

    /// Update threat score for an indicator
    pub async fn update_threat_score(&self, id: Uuid, score: i32) -> Result<()> {
        sqlx::query(
            "UPDATE indicators SET threat_score = $1, severity = $2, updated_at = NOW() WHERE id = $3"
        )
        .bind(score)
        .bind(Severity::from(score))
        .bind(id)
        .execute(&self.pool)
        .await
        .context("Failed to update threat score")?;

        Ok(())
    }

    /// Delete expired indicators
    pub async fn delete_expired(&self) -> Result<i64> {
        let result = sqlx::query(
            "DELETE FROM indicators WHERE expiration IS NOT NULL AND expiration < NOW()"
        )
        .execute(&self.pool)
        .await
        .context("Failed to delete expired indicators")?;

        Ok(result.rows_affected() as i64)
    }

    // ==================== Enrichments ====================

    /// Add enrichment data for an indicator
    pub async fn add_enrichment(
        &self,
        indicator_id: Uuid,
        enrichment_type: &str,
        provider: &str,
        data: serde_json::Value,
        ttl_hours: Option<i64>,
    ) -> Result<Enrichment> {
        let expires_at = ttl_hours.map(|h| Utc::now() + Duration::hours(h));

        let enrichment = sqlx::query_as::<_, Enrichment>(
            r#"
            INSERT INTO enrichments (id, indicator_id, enrichment_type, provider, data, fetched_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), $6)
            ON CONFLICT (indicator_id, enrichment_type, provider) DO UPDATE SET
                data = EXCLUDED.data,
                fetched_at = EXCLUDED.fetched_at,
                expires_at = EXCLUDED.expires_at
            RETURNING *
            "#
        )
        .bind(Uuid::new_v4())
        .bind(indicator_id)
        .bind(enrichment_type)
        .bind(provider)
        .bind(data)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await
        .context("Failed to add enrichment")?;

        Ok(enrichment)
    }

    /// Get enrichments for an indicator
    pub async fn get_enrichments(&self, indicator_id: Uuid) -> Result<Vec<Enrichment>> {
        let enrichments = sqlx::query_as::<_, Enrichment>(
            "SELECT * FROM enrichments WHERE indicator_id = $1 ORDER BY fetched_at DESC"
        )
        .bind(indicator_id)
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch enrichments")?;

        Ok(enrichments)
    }

    // ==================== Sightings ====================

    /// Record a sighting of an indicator
    pub async fn add_sighting(
        &self,
        indicator_id: Uuid,
        source: &str,
        context: Option<serde_json::Value>,
    ) -> Result<Sighting> {
        let sighting = sqlx::query_as::<_, Sighting>(
            r#"
            INSERT INTO sightings (id, indicator_id, source, context, observed_at, created_at)
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            RETURNING *
            "#
        )
        .bind(Uuid::new_v4())
        .bind(indicator_id)
        .bind(source)
        .bind(context)
        .fetch_one(&self.pool)
        .await
        .context("Failed to add sighting")?;

        // Update last_seen on indicator
        sqlx::query("UPDATE indicators SET last_seen = NOW() WHERE id = $1")
            .bind(indicator_id)
            .execute(&self.pool)
            .await?;

        Ok(sighting)
    }

    /// Count sightings for an indicator
    pub async fn count_sightings(&self, indicator_id: Uuid) -> Result<i64> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sightings WHERE indicator_id = $1"
        )
        .bind(indicator_id)
        .fetch_one(&self.pool)
        .await
        .context("Failed to count sightings")?;

        Ok(count.0)
    }

    // ==================== Sources ====================

    /// Create or update a source
    pub async fn upsert_source(&self, source: &IocSource) -> Result<IocSource> {
        let result = sqlx::query_as::<_, IocSource>(
            r#"
            INSERT INTO ioc_sources (id, name, source_type, url, api_key_required, reliability_score, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
            ON CONFLICT (name) DO UPDATE SET
                url = EXCLUDED.url,
                reliability_score = EXCLUDED.reliability_score,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(source.id)
        .bind(&source.name)
        .bind(&source.source_type)
        .bind(&source.url)
        .bind(source.api_key_required)
        .bind(source.reliability_score)
        .bind(source.enabled)
        .fetch_one(&self.pool)
        .await
        .context("Failed to upsert source")?;

        Ok(result)
    }

    /// Get all enabled sources
    pub async fn get_enabled_sources(&self) -> Result<Vec<IocSource>> {
        let sources = sqlx::query_as::<_, IocSource>(
            "SELECT * FROM ioc_sources WHERE enabled = true ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await
        .context("Failed to fetch sources")?;

        Ok(sources)
    }

    /// Update source last fetch time
    pub async fn update_source_fetch_time(&self, source_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE ioc_sources SET last_fetch = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await
            .context("Failed to update source fetch time")?;

        Ok(())
    }

    // ==================== Statistics ====================

    /// Get dashboard statistics
    pub async fn get_stats(&self) -> Result<DashboardStats> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM indicators")
            .fetch_one(&self.pool)
            .await?;

        let new_today: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM indicators WHERE created_at >= CURRENT_DATE"
        )
        .fetch_one(&self.pool)
        .await?;

        let new_this_week: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM indicators WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'"
        )
        .fetch_one(&self.pool)
        .await?;

        let active_sources: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM ioc_sources WHERE enabled = true"
        )
        .fetch_one(&self.pool)
        .await?;

        let recent_sightings: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sightings WHERE observed_at >= CURRENT_DATE - INTERVAL '24 hours'"
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(DashboardStats {
            total_indicators: total.0,
            indicators_by_type: std::collections::HashMap::new(), // TODO: implement
            indicators_by_severity: std::collections::HashMap::new(), // TODO: implement
            new_today: new_today.0,
            new_this_week: new_this_week.0,
            active_sources: active_sources.0,
            top_tags: vec![], // TODO: implement
            recent_sightings: recent_sightings.0,
        })
    }
}
