-- Create IOC type enum
CREATE TYPE ioc_type AS ENUM ('ip', 'domain', 'url', 'hash', 'email', 'cve');

-- Create severity enum
CREATE TYPE severity AS ENUM ('unknown', 'low', 'medium', 'high', 'critical');

-- Create TLP enum
CREATE TYPE tlp AS ENUM ('white', 'green', 'amber', 'red');

-- IOC Sources table
CREATE TABLE ioc_sources (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    source_type VARCHAR(50) NOT NULL, -- internal, feed, manual
    url TEXT,
    api_key_required BOOLEAN DEFAULT FALSE,
    reliability_score INTEGER DEFAULT 50 CHECK (reliability_score >= 0 AND reliability_score <= 100),
    enabled BOOLEAN DEFAULT TRUE,
    last_fetch TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Main indicators table
CREATE TABLE indicators (
    id UUID PRIMARY KEY,
    ioc_type ioc_type NOT NULL,
    value TEXT NOT NULL,
    severity severity NOT NULL DEFAULT 'unknown',
    confidence INTEGER DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
    threat_score INTEGER DEFAULT 50 CHECK (threat_score >= 0 AND threat_score <= 100),
    tlp tlp NOT NULL DEFAULT 'amber',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expiration TIMESTAMPTZ,
    tags TEXT[] DEFAULT '{}',
    source_ids UUID[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Unique constraint on type + value
    CONSTRAINT unique_indicator UNIQUE (ioc_type, value)
);

-- Index for fast lookups
CREATE INDEX idx_indicators_value ON indicators (value);
CREATE INDEX idx_indicators_type ON indicators (ioc_type);
CREATE INDEX idx_indicators_severity ON indicators (severity);
CREATE INDEX idx_indicators_threat_score ON indicators (threat_score);
CREATE INDEX idx_indicators_last_seen ON indicators (last_seen);
CREATE INDEX idx_indicators_tags ON indicators USING GIN (tags);
CREATE INDEX idx_indicators_expiration ON indicators (expiration) WHERE expiration IS NOT NULL;

-- Enrichments table
CREATE TABLE enrichments (
    id UUID PRIMARY KEY,
    indicator_id UUID NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    enrichment_type VARCHAR(50) NOT NULL, -- geoip, whois, dns, reputation
    provider VARCHAR(100) NOT NULL,
    data JSONB NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    
    -- One enrichment per type/provider per indicator
    CONSTRAINT unique_enrichment UNIQUE (indicator_id, enrichment_type, provider)
);

CREATE INDEX idx_enrichments_indicator ON enrichments (indicator_id);
CREATE INDEX idx_enrichments_type ON enrichments (enrichment_type);
CREATE INDEX idx_enrichments_expires ON enrichments (expires_at) WHERE expires_at IS NOT NULL;

-- Sightings table
CREATE TABLE sightings (
    id UUID PRIMARY KEY,
    indicator_id UUID NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
    source VARCHAR(255) NOT NULL,
    context JSONB,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sightings_indicator ON sightings (indicator_id);
CREATE INDEX idx_sightings_observed ON sightings (observed_at);

-- Insert default sources
INSERT INTO ioc_sources (id, name, source_type, url, api_key_required, reliability_score, enabled) VALUES
    ('00000000-0000-0000-0000-000000000001', 'honeytrap', 'internal', NULL, FALSE, 90, TRUE),
    ('00000000-0000-0000-0000-000000000002', 'manual', 'manual', NULL, FALSE, 80, TRUE),
    ('00000000-0000-0000-0000-000000000003', 'alienvault_otx', 'feed', 'https://otx.alienvault.com', TRUE, 70, TRUE),
    ('00000000-0000-0000-0000-000000000004', 'emerging_threats', 'feed', 'https://rules.emergingthreats.net', FALSE, 75, TRUE),
    ('00000000-0000-0000-0000-000000000005', 'abuseipdb', 'feed', 'https://abuseipdb.com', TRUE, 85, TRUE),
    ('00000000-0000-0000-0000-000000000006', 'feodo_tracker', 'feed', 'https://feodotracker.abuse.ch', FALSE, 80, TRUE);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_indicators_updated_at
    BEFORE UPDATE ON indicators
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sources_updated_at
    BEFORE UPDATE ON ioc_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
