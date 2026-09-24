import React from 'react';

function BatchDashboard({ batchResult, onNewAnalysis, onViewDetails }) {
  if (!batchResult || !batchResult.results) return null;

  const totalFiles = batchResult.total_files;
  const maliciousCount = batchResult.results.filter(r => r.prediction === 'MALICIOUS').length;
  const benignCount = batchResult.results.filter(r => r.prediction === 'BENIGN').length;
  const errorCount = batchResult.results.filter(r => r.prediction === 'ERROR').length;

  return (
    <div className="card">
      <div className="flex justify-between items-center mb-4">
        <h2>Dataset Scan Dashboard</h2>
        <button className="btn-secondary" onClick={onNewAnalysis}>New Analysis</button>
      </div>

      <div className="grid grid-3 gap-4 mb-4">
        <div style={{ background: '#f8f9fa', padding: '16px', borderRadius: '8px', textAlign: 'center' }}>
          <h3 style={{ margin: 0, fontSize: '2rem' }}>{totalFiles}</h3>
          <p style={{ margin: 0, color: 'var(--text-light)' }}>Total Files Scanned</p>
        </div>
        <div style={{ background: '#fff0f0', padding: '16px', borderRadius: '8px', textAlign: 'center', border: '1px solid #dc3545' }}>
          <h3 style={{ margin: 0, fontSize: '2rem', color: '#dc3545' }}>{maliciousCount}</h3>
          <p style={{ margin: 0, color: '#dc3545' }}>Malicious Detected</p>
        </div>
        <div style={{ background: '#f0fff0', padding: '16px', borderRadius: '8px', textAlign: 'center', border: '1px solid #28a745' }}>
          <h3 style={{ margin: 0, fontSize: '2rem', color: '#28a745' }}>{benignCount}</h3>
          <p style={{ margin: 0, color: '#28a745' }}>Benign / Safe</p>
        </div>
      </div>

      {errorCount > 0 && (
        <div className="alert-error mb-4">
          Failed to process {errorCount} files in the dataset.
        </div>
      )}

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
          <thead>
            <tr>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Filename</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Verdict</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Confidence</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Risk Level</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Threat Type</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Family</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Top Indicator</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #dee2e6', textAlign: 'left' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {batchResult.results.map((r, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #dee2e6', background: r.prediction === 'MALICIOUS' ? '#fff9f9' : (r.prediction === 'BENIGN' ? '#f9fff9' : '#fff') }}>
                <td style={{ padding: '12px' }}><strong>{r.filename}</strong></td>
                <td style={{ padding: '12px' }}>
                  <span className={`badge ${r.prediction === 'MALICIOUS' ? 'badge-danger' : (r.prediction === 'BENIGN' ? 'badge-success' : 'badge-warning')}`}>
                    {r.prediction}
                  </span>
                </td>
                <td style={{ padding: '12px' }}>{(r.confidence * 100).toFixed(1)}%</td>
                <td style={{ padding: '12px' }}>{r.risk_level}</td>
                <td style={{ padding: '12px', color: r.threat_type !== 'Clean' && r.threat_type !== 'Unknown' ? '#dc3545' : '#6c757d' }}>{r.threat_type}</td>
                <td style={{ padding: '12px', color: r.malware_family !== 'None' && r.malware_family !== 'Unknown' ? '#dc3545' : '#6c757d' }}>{r.malware_family}</td>
                <td style={{ padding: '12px', color: '#dc3545', fontSize: '0.85rem' }}>{r.top_malicious}</td>
                <td style={{ padding: '12px' }}>
                  {r.analysis_id && (
                    <button 
                      className="btn-secondary" 
                      style={{ padding: '4px 8px', fontSize: '0.8rem' }}
                      onClick={() => onViewDetails(r.analysis_id)}
                    >
                      View Details
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default BatchDashboard;
