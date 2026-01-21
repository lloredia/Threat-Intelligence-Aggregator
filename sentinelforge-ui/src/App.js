import React, { useState, useEffect } from 'react';

// SentinelForge Dashboard - Cyberpunk/Terminal Aesthetic
const API_BASE = 'http://localhost:8080';

// Utility to format dates
const formatDate = (dateStr) => {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  return date.toLocaleString('en-US', { 
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' 
  });
};

// Severity color mapping
const severityColors = {
  critical: { bg: '#ff0040', text: '#fff', glow: '0 0 20px rgba(255,0,64,0.6)' },
  high: { bg: '#ff6b00', text: '#fff', glow: '0 0 20px rgba(255,107,0,0.5)' },
  medium: { bg: '#ffd000', text: '#000', glow: '0 0 20px rgba(255,208,0,0.4)' },
  low: { bg: '#00d4aa', text: '#000', glow: '0 0 20px rgba(0,212,170,0.4)' },
  unknown: { bg: '#404040', text: '#888', glow: 'none' }
};

// IOC Type icons (ASCII art style)
const iocIcons = {
  ip: '◉',
  domain: '◈',
  url: '⛓',
  hash: '#',
  email: '@',
  cve: '⚠'
};

// Glitch text effect component
const GlitchText = ({ children, className = '' }) => (
  <span className={`glitch-text ${className}`} data-text={children}>
    {children}
  </span>
);

// Stat card component
const StatCard = ({ label, value, icon, trend }) => (
  <div className="stat-card">
    <div className="stat-icon">{icon}</div>
    <div className="stat-content">
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-label">{label}</div>
    </div>
    {trend && <div className={`stat-trend ${trend > 0 ? 'up' : 'down'}`}>
      {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}
    </div>}
  </div>
);

// Indicator row component
const IndicatorRow = ({ indicator, onClick }) => {
  const severity = severityColors[indicator.severity] || severityColors.unknown;
  
  return (
    <div className="indicator-row" onClick={() => onClick(indicator)}>
      <div className="ioc-type" title={indicator.ioc_type}>
        {iocIcons[indicator.ioc_type] || '?'}
      </div>
      <div className="ioc-value">
        <code>{indicator.value}</code>
      </div>
      <div 
        className="severity-badge" 
        style={{ 
          background: severity.bg, 
          color: severity.text,
          boxShadow: severity.glow 
        }}
      >
        {indicator.severity.toUpperCase()}
      </div>
      <div className="threat-score">
        <div className="score-bar">
          <div 
            className="score-fill" 
            style={{ width: `${indicator.threat_score}%` }}
          />
        </div>
        <span>{indicator.threat_score}</span>
      </div>
      <div className="tags">
        {indicator.tags?.slice(0, 3).map((tag, i) => (
          <span key={i} className="tag">{tag}</span>
        ))}
      </div>
      <div className="timestamp">{formatDate(indicator.last_seen)}</div>
    </div>
  );
};

// Detail panel component
const DetailPanel = ({ indicator, enrichments, onClose }) => {
  if (!indicator) return null;
  
  const severity = severityColors[indicator.severity] || severityColors.unknown;
  
  return (
    <div className="detail-panel">
      <div className="detail-header">
        <div className="detail-title">
          <span className="detail-icon">{iocIcons[indicator.ioc_type]}</span>
          <code>{indicator.value}</code>
        </div>
        <button className="close-btn" onClick={onClose}>×</button>
      </div>
      
      <div className="detail-grid">
        <div className="detail-item">
          <label>Type</label>
          <span>{indicator.ioc_type.toUpperCase()}</span>
        </div>
        <div className="detail-item">
          <label>Severity</label>
          <span 
            className="severity-inline"
            style={{ background: severity.bg, color: severity.text }}
          >
            {indicator.severity}
          </span>
        </div>
        <div className="detail-item">
          <label>Confidence</label>
          <span>{indicator.confidence}%</span>
        </div>
        <div className="detail-item">
          <label>Threat Score</label>
          <span>{indicator.threat_score}/100</span>
        </div>
        <div className="detail-item">
          <label>TLP</label>
          <span className={`tlp tlp-${indicator.tlp}`}>{indicator.tlp.toUpperCase()}</span>
        </div>
        <div className="detail-item">
          <label>First Seen</label>
          <span>{formatDate(indicator.first_seen)}</span>
        </div>
        <div className="detail-item">
          <label>Last Seen</label>
          <span>{formatDate(indicator.last_seen)}</span>
        </div>
        <div className="detail-item">
          <label>ID</label>
          <code className="uuid">{indicator.id}</code>
        </div>
      </div>
      
      {indicator.tags?.length > 0 && (
        <div className="detail-section">
          <h4>Tags</h4>
          <div className="tags-list">
            {indicator.tags.map((tag, i) => (
              <span key={i} className="tag">{tag}</span>
            ))}
          </div>
        </div>
      )}
      
      {enrichments?.length > 0 && (
        <div className="detail-section">
          <h4>Enrichment Data</h4>
          {enrichments.map((e, i) => (
            <div key={i} className="enrichment-block">
              <div className="enrichment-header">
                <span className="enrichment-type">{e.enrichment_type}</span>
                <span className="enrichment-provider">{e.provider}</span>
              </div>
              <pre className="enrichment-data">
                {JSON.stringify(e.data, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// Add indicator modal
const AddIndicatorModal = ({ isOpen, onClose, onSubmit }) => {
  const [value, setValue] = useState('');
  const [severity, setSeverity] = useState('unknown');
  const [tags, setTags] = useState('');
  const [loading, setLoading] = useState(false);
  
  if (!isOpen) return null;
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onSubmit({
      value,
      severity,
      tags: tags ? tags.split(',').map(t => t.trim()) : []
    });
    setLoading(false);
    setValue('');
    setTags('');
    onClose();
  };
  
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <GlitchText>ADD INDICATOR</GlitchText>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>IOC Value</label>
            <input
              type="text"
              value={value}
              onChange={e => setValue(e.target.value)}
              placeholder="IP, domain, hash, URL, email, or CVE..."
              required
              autoFocus
            />
            <span className="input-hint">Type auto-detected from value</span>
          </div>
          <div className="form-group">
            <label>Severity</label>
            <select value={severity} onChange={e => setSeverity(e.target.value)}>
              <option value="unknown">Unknown</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div className="form-group">
            <label>Tags</label>
            <input
              type="text"
              value={tags}
              onChange={e => setTags(e.target.value)}
              placeholder="phishing, malware, c2 (comma separated)"
            />
          </div>
          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Adding...' : 'Add Indicator'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Main Dashboard Component
export default function SentinelForgeDashboard() {
  const [stats, setStats] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [enrichments, setEnrichments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');
  
  // Fetch data
  const fetchData = async () => {
    try {
      const [statsRes, indicatorsRes] = await Promise.all([
        fetch(`${API_BASE}/api/v1/stats`),
        fetch(`${API_BASE}/api/v1/indicators`)
      ]);
      
      if (!statsRes.ok || !indicatorsRes.ok) throw new Error('API Error');
      
      setStats(await statsRes.json());
      const data = await indicatorsRes.json();
      setIndicators(data.data || []);
      setError(null);
    } catch (err) {
      setError('Failed to connect to SentinelForge API');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
  
  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, []);
  
  // Fetch indicator details
  const handleSelectIndicator = async (indicator) => {
    setSelectedIndicator(indicator);
    try {
      const res = await fetch(`${API_BASE}/api/v1/indicators/${indicator.id}`);
      if (res.ok) {
        const data = await res.json();
        setEnrichments(data.enrichments || []);
      }
    } catch (err) {
      console.error('Failed to fetch enrichments:', err);
    }
  };
  
  // Add new indicator
  const handleAddIndicator = async (data) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/indicators`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (res.ok) {
        fetchData(); // Refresh list
      }
    } catch (err) {
      console.error('Failed to add indicator:', err);
    }
  };
  
  // Filter indicators
  const filteredIndicators = indicators.filter(ind => {
    const matchesSearch = !searchQuery || 
      ind.value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ind.tags?.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = filterType === 'all' || ind.ioc_type === filterType;
    return matchesSearch && matchesType;
  });

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@400;700;900&display=swap');
        
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        
        :root {
          --bg-primary: #0a0a0f;
          --bg-secondary: #12121a;
          --bg-tertiary: #1a1a25;
          --border: #2a2a3a;
          --text-primary: #e0e0e0;
          --text-secondary: #888;
          --accent: #00ffaa;
          --accent-dim: #00aa77;
          --danger: #ff0040;
          --warning: #ffd000;
        }
        
        body {
          font-family: 'JetBrains Mono', monospace;
          background: var(--bg-primary);
          color: var(--text-primary);
          min-height: 100vh;
        }
        
        .dashboard {
          display: grid;
          grid-template-columns: 1fr 380px;
          grid-template-rows: auto 1fr;
          min-height: 100vh;
          gap: 1px;
          background: var(--border);
        }
        
        .dashboard.no-detail {
          grid-template-columns: 1fr;
        }
        
        /* Header */
        .header {
          grid-column: 1 / -1;
          background: var(--bg-secondary);
          padding: 1rem 2rem;
          display: flex;
          align-items: center;
          justify-content: space-between;
          border-bottom: 1px solid var(--accent);
          position: relative;
          overflow: hidden;
        }
        
        .header::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 1px;
          background: linear-gradient(90deg, transparent, var(--accent), transparent);
          animation: scan 3s linear infinite;
        }
        
        @keyframes scan {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        
        .logo {
          display: flex;
          align-items: center;
          gap: 1rem;
        }
        
        .logo-icon {
          width: 48px;
          height: 48px;
          background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dim) 100%);
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 24px;
          color: var(--bg-primary);
          font-weight: bold;
          box-shadow: 0 0 30px rgba(0, 255, 170, 0.3);
        }
        
        .logo-text {
          font-family: 'Orbitron', sans-serif;
          font-size: 1.5rem;
          font-weight: 900;
          letter-spacing: 2px;
          background: linear-gradient(90deg, var(--accent), #fff);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
        
        .logo-subtitle {
          font-size: 0.65rem;
          color: var(--text-secondary);
          letter-spacing: 4px;
          text-transform: uppercase;
        }
        
        .header-actions {
          display: flex;
          gap: 1rem;
          align-items: center;
        }
        
        .btn-primary {
          background: var(--accent);
          color: var(--bg-primary);
          border: none;
          padding: 0.75rem 1.5rem;
          font-family: inherit;
          font-weight: 700;
          cursor: pointer;
          transition: all 0.2s;
          text-transform: uppercase;
          letter-spacing: 1px;
          font-size: 0.8rem;
        }
        
        .btn-primary:hover {
          box-shadow: 0 0 20px rgba(0, 255, 170, 0.5);
          transform: translateY(-1px);
        }
        
        .btn-secondary {
          background: transparent;
          color: var(--text-primary);
          border: 1px solid var(--border);
          padding: 0.75rem 1.5rem;
          font-family: inherit;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-secondary:hover {
          border-color: var(--accent);
          color: var(--accent);
        }
        
        /* Main content */
        .main-content {
          background: var(--bg-primary);
          display: flex;
          flex-direction: column;
          overflow: hidden;
        }
        
        /* Stats bar */
        .stats-bar {
          display: flex;
          gap: 1px;
          background: var(--border);
          border-bottom: 1px solid var(--border);
        }
        
        .stat-card {
          flex: 1;
          background: var(--bg-secondary);
          padding: 1.25rem 1.5rem;
          display: flex;
          align-items: center;
          gap: 1rem;
        }
        
        .stat-icon {
          font-size: 2rem;
          opacity: 0.5;
        }
        
        .stat-value {
          font-family: 'Orbitron', sans-serif;
          font-size: 1.75rem;
          font-weight: 700;
          color: var(--accent);
        }
        
        .stat-label {
          font-size: 0.7rem;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        .stat-trend {
          font-size: 0.8rem;
          padding: 0.25rem 0.5rem;
          border-radius: 4px;
        }
        
        .stat-trend.up {
          color: var(--accent);
          background: rgba(0, 255, 170, 0.1);
        }
        
        .stat-trend.down {
          color: var(--danger);
          background: rgba(255, 0, 64, 0.1);
        }
        
        /* Toolbar */
        .toolbar {
          display: flex;
          gap: 1rem;
          padding: 1rem 1.5rem;
          background: var(--bg-secondary);
          border-bottom: 1px solid var(--border);
          align-items: center;
        }
        
        .search-box {
          flex: 1;
          position: relative;
        }
        
        .search-box input {
          width: 100%;
          background: var(--bg-tertiary);
          border: 1px solid var(--border);
          padding: 0.75rem 1rem 0.75rem 2.5rem;
          color: var(--text-primary);
          font-family: inherit;
          font-size: 0.9rem;
        }
        
        .search-box input:focus {
          outline: none;
          border-color: var(--accent);
          box-shadow: 0 0 10px rgba(0, 255, 170, 0.2);
        }
        
        .search-box::before {
          content: '⌕';
          position: absolute;
          left: 0.75rem;
          top: 50%;
          transform: translateY(-50%);
          color: var(--text-secondary);
        }
        
        .filter-select {
          background: var(--bg-tertiary);
          border: 1px solid var(--border);
          padding: 0.75rem 1rem;
          color: var(--text-primary);
          font-family: inherit;
          cursor: pointer;
        }
        
        .filter-select:focus {
          outline: none;
          border-color: var(--accent);
        }
        
        /* Indicators list */
        .indicators-list {
          flex: 1;
          overflow-y: auto;
          background: var(--bg-primary);
        }
        
        .list-header {
          display: grid;
          grid-template-columns: 50px 1fr 100px 120px 150px 140px;
          gap: 1rem;
          padding: 0.75rem 1.5rem;
          background: var(--bg-tertiary);
          font-size: 0.7rem;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: var(--text-secondary);
          border-bottom: 1px solid var(--border);
          position: sticky;
          top: 0;
          z-index: 10;
        }
        
        .indicator-row {
          display: grid;
          grid-template-columns: 50px 1fr 100px 120px 150px 140px;
          gap: 1rem;
          padding: 1rem 1.5rem;
          border-bottom: 1px solid var(--border);
          cursor: pointer;
          transition: all 0.15s;
          align-items: center;
        }
        
        .indicator-row:hover {
          background: var(--bg-secondary);
          border-left: 3px solid var(--accent);
          padding-left: calc(1.5rem - 3px);
        }
        
        .ioc-type {
          font-size: 1.5rem;
          text-align: center;
          opacity: 0.7;
        }
        
        .ioc-value code {
          font-size: 0.85rem;
          color: var(--accent);
          word-break: break-all;
        }
        
        .severity-badge {
          padding: 0.3rem 0.6rem;
          font-size: 0.65rem;
          font-weight: 700;
          text-align: center;
          letter-spacing: 1px;
        }
        
        .threat-score {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        
        .score-bar {
          flex: 1;
          height: 6px;
          background: var(--bg-tertiary);
          border-radius: 3px;
          overflow: hidden;
        }
        
        .score-fill {
          height: 100%;
          background: linear-gradient(90deg, var(--accent), var(--warning), var(--danger));
          transition: width 0.3s;
        }
        
        .threat-score span {
          font-size: 0.8rem;
          min-width: 24px;
          text-align: right;
        }
        
        .tags {
          display: flex;
          gap: 0.25rem;
          flex-wrap: wrap;
        }
        
        .tag {
          background: var(--bg-tertiary);
          padding: 0.2rem 0.5rem;
          font-size: 0.65rem;
          border: 1px solid var(--border);
          color: var(--text-secondary);
        }
        
        .timestamp {
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
        
        /* Detail panel */
        .detail-panel {
          background: var(--bg-secondary);
          border-left: 1px solid var(--border);
          overflow-y: auto;
          display: flex;
          flex-direction: column;
        }
        
        .detail-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1.25rem;
          border-bottom: 1px solid var(--border);
          background: var(--bg-tertiary);
        }
        
        .detail-title {
          display: flex;
          align-items: center;
          gap: 0.75rem;
        }
        
        .detail-icon {
          font-size: 1.5rem;
        }
        
        .detail-title code {
          font-size: 0.85rem;
          color: var(--accent);
          word-break: break-all;
        }
        
        .close-btn {
          background: transparent;
          border: none;
          color: var(--text-secondary);
          font-size: 1.5rem;
          cursor: pointer;
          line-height: 1;
          padding: 0.25rem;
        }
        
        .close-btn:hover {
          color: var(--danger);
        }
        
        .detail-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1px;
          background: var(--border);
          margin: 1rem;
          border: 1px solid var(--border);
        }
        
        .detail-item {
          background: var(--bg-primary);
          padding: 0.75rem;
        }
        
        .detail-item label {
          display: block;
          font-size: 0.65rem;
          color: var(--text-secondary);
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 0.25rem;
        }
        
        .detail-item span, .detail-item code {
          font-size: 0.85rem;
        }
        
        .detail-item .uuid {
          font-size: 0.65rem;
          color: var(--text-secondary);
          word-break: break-all;
        }
        
        .severity-inline {
          padding: 0.2rem 0.5rem;
          font-size: 0.7rem;
          font-weight: 600;
        }
        
        .tlp {
          padding: 0.2rem 0.5rem;
          font-size: 0.7rem;
          font-weight: 600;
        }
        
        .tlp-white { background: #fff; color: #000; }
        .tlp-green { background: #00aa00; color: #fff; }
        .tlp-amber { background: #ffaa00; color: #000; }
        .tlp-red { background: #ff0000; color: #fff; }
        
        .detail-section {
          padding: 1rem;
          border-top: 1px solid var(--border);
        }
        
        .detail-section h4 {
          font-size: 0.7rem;
          text-transform: uppercase;
          letter-spacing: 2px;
          color: var(--accent);
          margin-bottom: 0.75rem;
        }
        
        .tags-list {
          display: flex;
          gap: 0.5rem;
          flex-wrap: wrap;
        }
        
        .enrichment-block {
          background: var(--bg-primary);
          border: 1px solid var(--border);
          margin-bottom: 0.75rem;
        }
        
        .enrichment-header {
          display: flex;
          justify-content: space-between;
          padding: 0.5rem 0.75rem;
          background: var(--bg-tertiary);
          border-bottom: 1px solid var(--border);
        }
        
        .enrichment-type {
          font-weight: 600;
          text-transform: uppercase;
          font-size: 0.7rem;
          color: var(--accent);
        }
        
        .enrichment-provider {
          font-size: 0.7rem;
          color: var(--text-secondary);
        }
        
        .enrichment-data {
          padding: 0.75rem;
          font-size: 0.75rem;
          overflow-x: auto;
          color: var(--text-secondary);
          margin: 0;
        }
        
        /* Modal */
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.8);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          backdrop-filter: blur(4px);
        }
        
        .modal {
          background: var(--bg-secondary);
          border: 1px solid var(--accent);
          width: 100%;
          max-width: 500px;
          box-shadow: 0 0 60px rgba(0, 255, 170, 0.2);
        }
        
        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 1.25rem;
          border-bottom: 1px solid var(--border);
          font-family: 'Orbitron', sans-serif;
          font-size: 0.9rem;
          letter-spacing: 2px;
        }
        
        .modal form {
          padding: 1.5rem;
        }
        
        .form-group {
          margin-bottom: 1.25rem;
        }
        
        .form-group label {
          display: block;
          font-size: 0.7rem;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: var(--text-secondary);
          margin-bottom: 0.5rem;
        }
        
        .form-group input,
        .form-group select {
          width: 100%;
          background: var(--bg-tertiary);
          border: 1px solid var(--border);
          padding: 0.75rem;
          color: var(--text-primary);
          font-family: inherit;
          font-size: 0.9rem;
        }
        
        .form-group input:focus,
        .form-group select:focus {
          outline: none;
          border-color: var(--accent);
        }
        
        .input-hint {
          font-size: 0.7rem;
          color: var(--text-secondary);
          margin-top: 0.25rem;
          display: block;
        }
        
        .form-actions {
          display: flex;
          gap: 1rem;
          justify-content: flex-end;
          margin-top: 1.5rem;
        }
        
        /* Loading & Error states */
        .loading, .error-state {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100vh;
          flex-direction: column;
          gap: 1rem;
        }
        
        .loading-spinner {
          width: 60px;
          height: 60px;
          border: 3px solid var(--border);
          border-top-color: var(--accent);
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        
        .error-state {
          color: var(--danger);
        }
        
        .error-state button {
          margin-top: 1rem;
        }
        
        /* Empty state */
        .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 4rem 2rem;
          color: var(--text-secondary);
          text-align: center;
        }
        
        .empty-icon {
          font-size: 4rem;
          margin-bottom: 1rem;
          opacity: 0.3;
        }
        
        /* Glitch effect */
        .glitch-text {
          position: relative;
        }
        
        .glitch-text::before,
        .glitch-text::after {
          content: attr(data-text);
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
        }
        
        .glitch-text::before {
          left: 2px;
          text-shadow: -2px 0 var(--danger);
          clip: rect(24px, 550px, 90px, 0);
          animation: glitch-anim 3s infinite linear alternate-reverse;
        }
        
        .glitch-text::after {
          left: -2px;
          text-shadow: -2px 0 var(--accent);
          clip: rect(85px, 550px, 140px, 0);
          animation: glitch-anim 2s infinite linear alternate-reverse;
        }
        
        @keyframes glitch-anim {
          0% { clip: rect(10px, 9999px, 31px, 0); }
          10% { clip: rect(70px, 9999px, 95px, 0); }
          20% { clip: rect(15px, 9999px, 72px, 0); }
          30% { clip: rect(45px, 9999px, 15px, 0); }
          40% { clip: rect(78px, 9999px, 54px, 0); }
          50% { clip: rect(22px, 9999px, 76px, 0); }
          60% { clip: rect(61px, 9999px, 43px, 0); }
          70% { clip: rect(5px, 9999px, 89px, 0); }
          80% { clip: rect(36px, 9999px, 98px, 0); }
          90% { clip: rect(83px, 9999px, 28px, 0); }
          100% { clip: rect(48px, 9999px, 62px, 0); }
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
          width: 8px;
          height: 8px;
        }
        
        ::-webkit-scrollbar-track {
          background: var(--bg-primary);
        }
        
        ::-webkit-scrollbar-thumb {
          background: var(--border);
        }
        
        ::-webkit-scrollbar-thumb:hover {
          background: var(--accent-dim);
        }
      `}</style>
      
      {loading ? (
        <div className="loading">
          <div className="loading-spinner" />
          <span>Connecting to SentinelForge...</span>
        </div>
      ) : error ? (
        <div className="error-state">
          <div style={{ fontSize: '3rem' }}>⚠</div>
          <div>{error}</div>
          <button className="btn-primary" onClick={fetchData}>Retry Connection</button>
        </div>
      ) : (
        <div className={`dashboard ${!selectedIndicator ? 'no-detail' : ''}`}>
          <header className="header">
            <div className="logo">
              <div className="logo-icon">SF</div>
              <div>
                <div className="logo-text">SENTINELFORGE</div>
                <div className="logo-subtitle">Threat Intelligence Platform</div>
              </div>
            </div>
            <div className="header-actions">
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                {new Date().toLocaleString()}
              </span>
              <button className="btn-primary" onClick={() => setShowAddModal(true)}>
                + Add IOC
              </button>
            </div>
          </header>
          
          <main className="main-content">
            <div className="stats-bar">
              <StatCard 
                label="Total IOCs" 
                value={stats?.total_indicators || 0} 
                icon="◉"
              />
              <StatCard 
                label="New Today" 
                value={stats?.new_today || 0} 
                icon="+"
                trend={stats?.new_today}
              />
              <StatCard 
                label="This Week" 
                value={stats?.new_this_week || 0} 
                icon="◷"
              />
              <StatCard 
                label="Active Feeds" 
                value={stats?.active_sources || 0} 
                icon="⚡"
              />
              <StatCard 
                label="Sightings (24h)" 
                value={stats?.recent_sightings || 0} 
                icon="👁"
              />
            </div>
            
            <div className="toolbar">
              <div className="search-box">
                <input
                  type="text"
                  placeholder="Search indicators, tags..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                />
              </div>
              <select 
                className="filter-select"
                value={filterType}
                onChange={e => setFilterType(e.target.value)}
              >
                <option value="all">All Types</option>
                <option value="ip">IP Addresses</option>
                <option value="domain">Domains</option>
                <option value="url">URLs</option>
                <option value="hash">Hashes</option>
                <option value="email">Emails</option>
                <option value="cve">CVEs</option>
              </select>
            </div>
            
            <div className="indicators-list">
              <div className="list-header">
                <span>Type</span>
                <span>Value</span>
                <span>Severity</span>
                <span>Threat Score</span>
                <span>Tags</span>
                <span>Last Seen</span>
              </div>
              
              {filteredIndicators.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">◉</div>
                  <div>No indicators found</div>
                  <div style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>
                    Add your first IOC to get started
                  </div>
                </div>
              ) : (
                filteredIndicators.map(indicator => (
                  <IndicatorRow
                    key={indicator.id}
                    indicator={indicator}
                    onClick={handleSelectIndicator}
                  />
                ))
              )}
            </div>
          </main>
          
          {selectedIndicator && (
            <DetailPanel
              indicator={selectedIndicator}
              enrichments={enrichments}
              onClose={() => {
                setSelectedIndicator(null);
                setEnrichments([]);
              }}
            />
          )}
        </div>
      )}
      
      <AddIndicatorModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onSubmit={handleAddIndicator}
      />
    </>
  );
}
