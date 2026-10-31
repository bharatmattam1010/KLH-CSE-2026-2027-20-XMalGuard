import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

function AnalysisHistory({ onViewAnalysis }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);
  const limit = 10;

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory(page * limit, limit);
      setHistory(data);
    } catch (err) {
      console.error(err);
      setError('Failed to load history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [page]);

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this analysis record?')) return;
    
    try {
      await api.deleteAnalysis(id);
      fetchHistory();
    } catch (err) {
      console.error(err);
      alert('Failed to delete record');
    }
  };

  const truncate = (str, len = 12) => {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
  };

  const getBadgeClass = (lvl) => {
    switch (lvl?.toLowerCase()) {
      case 'low': return 'badge-low';
      case 'medium': return 'badge-medium';
      case 'high': return 'badge-high';
      case 'critical': return 'badge-critical';
      default: return 'badge-medium';
    }
  };

  const checkIsMalicious = (record) => {
    if (!record) return false;
    if (record.prediction?.is_malicious !== undefined) return Boolean(record.prediction.is_malicious);
    if (typeof record.prediction === 'string') return record.prediction.toLowerCase() === 'malicious';
    if (typeof record.prediction?.prediction === 'string') return record.prediction.prediction.toLowerCase() === 'malicious';
    return false;
  };

  const getConfidence = (record) => {
    const c = record.prediction?.confidence ?? record.confidence ?? 0;
    return (Number(c) * 100).toFixed(0);
  };

  if (loading && history.length === 0) return <div>Loading history...</div>;
  if (error) return <div className="alert-error">{error}</div>;

  const maliciousCount = history.filter(checkIsMalicious).length;
  const benignCount = history.length - maliciousCount;

  return (
    <div className="card">
      <h2 className="mb-4">Analysis History</h2>
      
      {history.length === 0 ? (
        <p className="text-light">No analysis history found. Upload a PE file to get started.</p>
      ) : (
        <>
          <div style={{ display: 'flex', gap: '15px', marginBottom: '20px', flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: '120px', padding: '15px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: 'var(--primary)' }}>{history.length}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Total Scans</div>
            </div>
            <div style={{ flex: 1, minWidth: '120px', padding: '15px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#dc3545' }}>
                {maliciousCount}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Malicious Detected</div>
            </div>
            <div style={{ flex: 1, minWidth: '120px', padding: '15px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#28a745' }}>
                {benignCount}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Benign Files</div>
            </div>
            <div style={{ flex: 1, minWidth: '120px', padding: '15px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#fd7e14' }}>
                {history.filter(r => (r.risk_assessment?.level === 'HIGH' || r.risk_assessment?.level === 'CRITICAL' || r.risk_level === 'HIGH' || r.risk_level === 'CRITICAL')).length}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>High/Critical Risk</div>
            </div>
          </div>
          
          <div style={{overflowX: 'auto'}}>
          <table>
            <thead>
              <tr>
                <th>Filename</th>
                <th>SHA-256</th>
                <th>Date</th>
                <th>Verdict</th>
                <th>Risk Score</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map((record) => {
                const isMal = checkIsMalicious(record);
                const filename = record.file_info?.filename || record.filename || 'Unknown';
                const sha = record.file_info?.hashes?.sha256 || record.sha256 || '';
                const dateStr = record.created_at || record.timestamp || '';
                const riskLevel = record.risk_assessment?.level || record.risk_level || (isMal ? 'CRITICAL' : 'LOW');
                const riskScore = record.risk_assessment?.score ?? record.risk_score ?? (isMal ? 75 : 10);

                return (
                  <tr 
                    key={record.id} 
                    onClick={() => onViewAnalysis(record)}
                    style={{cursor: 'pointer'}}
                  >
                    <td style={{fontWeight: '500'}}>{filename}</td>
                    <td style={{fontFamily: 'monospace'}}>{truncate(sha)}</td>
                    <td>{dateStr ? new Date(dateStr).toLocaleString() : 'N/A'}</td>
                    <td>
                      <span className={`badge ${isMal ? 'badge-critical' : 'badge-low'}`}>
                        {isMal ? 'MALICIOUS' : 'BENIGN'} ({getConfidence(record)}%)
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${getBadgeClass(riskLevel)}`}>
                        {Number(riskScore).toFixed(0)} - {riskLevel}
                      </span>
                    </td>
                    <td>
                      <button 
                        className="btn-danger"
                        style={{padding: '4px 8px', fontSize: '0.8rem'}}
                        onClick={(e) => handleDelete(record.id, e)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        </>
      )}
    </div>
  );
}

export default AnalysisHistory;
