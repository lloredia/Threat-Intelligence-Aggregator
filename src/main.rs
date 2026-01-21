//! SentinelForge
//! 
//! A service for collecting, enriching, and serving threat intelligence data.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod collectors;
mod enrichment;
mod models;
mod storage;

use api::{create_router, AppState};
use enrichment::{EnrichmentEngine, geoip::GeoIpProvider, dns::DnsProvider, abuseipdb::AbuseIpDbProvider, virustotal::VirusTotalProvider};
use storage::ThreatIntelRepo;

/// SentinelForge
#[derive(Parser, Debug)]
#[command(name = "sentinelforge")]
#[command(about = "Collect, enrich, and serve threat intelligence")]
struct Args {
    /// Server host
    #[arg(long, env = "HOST", default_value = "0.0.0.0")]
    host: String,

    /// Server port
    #[arg(long, env = "PORT", default_value = "8080")]
    port: u16,

    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// GeoIP city database path
    #[arg(long, env = "GEOIP_CITY_DB")]
    geoip_city_db: Option<String>,

    /// GeoIP ASN database path
    #[arg(long, env = "GEOIP_ASN_DB")]
    geoip_asn_db: Option<String>,

    /// AbuseIPDB API key
    #[arg(long, env = "ABUSEIPDB_API_KEY")]
    abuseipdb_api_key: Option<String>,

    /// VirusTotal API key
    #[arg(long, env = "VIRUSTOTAL_API_KEY")]
    virustotal_api_key: Option<String>,

    /// Run database migrations
    #[arg(long, default_value = "false")]
    migrate: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file if present
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinelforge=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse arguments
    let args = Args::parse();

    tracing::info!("Starting SentinelForge");

    // Connect to database
    let repo = ThreatIntelRepo::new(&args.database_url)
        .await
        .context("Failed to connect to database")?;

    // Run migrations if requested
    if args.migrate {
        tracing::info!("Running database migrations...");
        repo.migrate().await?;
        tracing::info!("Migrations complete");
    }

    // Setup enrichment engine
    let mut enrichment = EnrichmentEngine::new();

    // Add GeoIP provider
    if let Ok(geoip) = GeoIpProvider::new(
        args.geoip_city_db.as_ref().map(Path::new),
        args.geoip_asn_db.as_ref().map(Path::new),
    ) {
        tracing::info!("GeoIP enrichment enabled");
        enrichment.add_provider(Box::new(geoip));
    }

    // Add DNS provider
    if let Ok(dns) = DnsProvider::new().await {
        tracing::info!("DNS enrichment enabled");
        enrichment.add_provider(Box::new(dns));
    }

    // Add AbuseIPDB provider
    if let Some(api_key) = args.abuseipdb_api_key {
        tracing::info!("AbuseIPDB enrichment enabled");
        enrichment.add_provider(Box::new(AbuseIpDbProvider::new(api_key)));
    }

    // Add VirusTotal provider
    if let Some(api_key) = args.virustotal_api_key {
        tracing::info!("VirusTotal enrichment enabled");
        enrichment.add_provider(Box::new(VirusTotalProvider::new(api_key)));
    }

    // Create application state
    let state = Arc::new(AppState {
        repo,
        enrichment: Arc::new(enrichment),
    });

    // Setup CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Create router
    let app = create_router(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    // Start server
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!("Listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
