import React from 'react';

function RiskAssessment({ assessment }) {
  if (!assessment) return null;

  const { score, level, component_scores, factors, recommendation } = assessment;

  const getBadgeClass = (lvl) => {
    switch (lvl?.toLowerCase()) {
      case 'low': return 'badge-low';
      case 'medium': return 'badge-medium';
      case 'high': return 'badge-high';
      case 'critical': return 'badge-critical';
      default: return 'badge-medium';
    }
  };

  return (
    <div className="card flex flex-col justify-between">
      <div>
        <div className="flex justify-between items-center mb-4">
          <h3 style={{margin: 0}}>Risk Assessment</h3>
          <span className={`badge ${getBadgeClass(level)}`} style={{fontSize: '1.2em', padding: '6px 12px'}}>{level} RISK</span>
        </div>
        
        <div className="flex items-end gap-2 mb-4">
          <span style={{fontSize: '3rem', fontWeight: 'bold', lineHeight: 1}}>{score?.toFixed(0)}</span>
          <span style={{fontSize: '1.5rem', color: 'var(--text-light)', paddingBottom: '4px'}}>/ 100</span>
        </div>

        <div className="mb-4">
          <h4 style={{fontSize: '0.9rem', color: 'var(--text-light)', marginBottom: '8px', textTransform: 'uppercase'}}>Score Components</h4>
          {component_scores && Object.entries(component_scores).map(([key, val]) => (
            <div key={key} style={{marginBottom: '6px'}}>
              <div className="flex justify-between" style={{fontSize: '0.85rem', marginBottom: '2px'}}>
                <span style={{textTransform: 'capitalize'}}>{key.replace('_', ' ')}</span>
                <span>{val.toFixed(1)}</span>
              </div>
              <div style={{width: '100%', backgroundColor: 'var(--border)', height: '6px', borderRadius: '3px'}}>
                <div style={{width: `${Math.min(val, 100)}%`, backgroundColor: 'var(--accent)', height: '100%', borderRadius: '3px'}}></div>
              </div>
            </div>
          ))}
        </div>

        {factors && factors.length > 0 && (
          <div className="mb-4">
            <h4 style={{fontSize: '0.9rem', color: 'var(--text-light)', marginBottom: '8px', textTransform: 'uppercase'}}>Key Factors</h4>
            <ul style={{paddingLeft: '20px', margin: 0, fontSize: '0.9rem'}}>
              {factors.map((f, i) => <li key={i}>{f}</li>)}
            </ul>
          </div>
        )}
      </div>

      {recommendation && (
        <div style={{backgroundColor: '#e9ecef', padding: '12px', borderRadius: '8px', fontSize: '0.9rem', borderLeft: '4px solid var(--accent)'}}>
          <strong>Recommendation:</strong> {recommendation}
        </div>
      )}
    </div>
  );
}

export default RiskAssessment;
