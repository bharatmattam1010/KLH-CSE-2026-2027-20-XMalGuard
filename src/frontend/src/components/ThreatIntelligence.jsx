import React from 'react';

function ThreatIntelligence({ threatIntel }) {
  if (!threatIntel) return null;

  if (!threatIntel.available) {
    return (
      <div className="card" style={{backgroundColor: '#f8f9fa'}}>
        <h3 className="mb-4">Threat Intelligence</h3>
        <p style={{color: 'var(--text-light)'}}>
          Threat intelligence data not available. Configure an API key for external threat intelligence lookups. Local static analysis results are shown above.
        </p>
      </div>
    );
  }

  const { provider, detections, total_engines, malware_family, tags, is_mock, last_analysis_date } = threatIntel;
  const detectionRate = (detections / (total_engines || 1)) * 100;
  
  let rateColor = 'var(--success)';
  if (detectionRate > 10) rateColor = 'var(--warning)';
  if (detectionRate > 50) rateColor = 'var(--danger)';

  return (
    <div className="card border-l-4" style={{borderLeftColor: rateColor, borderLeftWidth: '4px'}}>
      <h3 className="mb-4">Threat Intelligence</h3>
      
      {is_mock && (
        <div style={{backgroundColor: '#fff3cd', color: '#856404', padding: '10px', borderRadius: '4px', marginBottom: '16px', fontSize: '0.9rem'}}>
          ⚠️ This is simulated threat intelligence data for demonstration purposes.
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div>
          <p><strong>Provider:</strong> {provider}</p>
          <p><strong>Detections:</strong> <span style={{color: rateColor, fontWeight: 'bold'}}>{detections} / {total_engines} engines</span></p>
          <p><strong>Detection Rate:</strong> {detectionRate.toFixed(1)}%</p>
        </div>
        <div>
          <p><strong>Malware Family:</strong> {malware_family || 'Unknown'}</p>
          <p><strong>Last Analysis:</strong> {last_analysis_date || 'N/A'}</p>
          <p><strong>Tags:</strong></p>
          <div style={{display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '4px'}}>
            {tags && tags.map((tag, i) => (
              <span key={i} className="badge" style={{backgroundColor: '#e2e8f0', color: '#475569'}}>{tag}</span>
            ))}
            {(!tags || tags.length === 0) && <span style={{fontSize: '0.9rem', color: 'var(--text-light)'}}>None</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

export default ThreatIntelligence;
