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

  if (loading && history.length === 0) return <div>Loading history...</div>;
  if (error) return <div className="alert-error">{error}</div>;

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
                {history.filter(r => r.prediction?.is_malicious).length}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Malicious Detected</div>
            </div>
            <div style={{ flex: 1, minWidth: '120px', padding: '15px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#28a745' }}>
                {history.filter(r => !r.prediction?.is_malicious).length}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-light)', textTransform: 'uppercase' }}>Benign Files</div>
            </div>
            <div style={{ flex: 1, minWidth: '120px', padding: '15px', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: '8px', textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#fd7e14' }}>
                {history.filter(r => r.risk_assessment?.level === 'HIGH' || r.risk_assessment?.level === 'CRITICAL').length}
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
                <th>Prediction</th>
                <th>Risk Score</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map((record) => (
                <tr 
                  key={record.id} 
                  onClick={() => onViewAnalysis(record)}
                  style={{cursor: 'pointer'}}
                >
                  <td style={{fontWeight: '500'}}>{record.file_info?.filename}</td>
                  <td style={{fontFamily: 'monospace'}}>{truncate(record.file_info?.hashes?.sha256)}</td>
                  <td>{new Date(record.created_at).toLocaleString()}</td>
                  <td>
                    <span className={`badge ${record.prediction?.is_malicious ? 'badge-critical' : 'badge-low'}`}>
                      {record.prediction?.is_malicious ? 'MALICIOUS' : 'BENIGN'} 
                      ({(record.prediction?.confidence * 100).toFixed(0)}%)
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${getBadgeClass(record.risk_assessment?.level)}`}>
                      {record.risk_assessment?.score?.toFixed(0) || 0} - {record.risk_assessment?.level || 'UNKNOWN'}
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
              ))}
            </tbody>
          </table>
        </div>
        </>
      )}
      
      <div className="flex justify-between mt-4">
        <button 
          onClick={() => setPage(p => Math.max(0, p - 1))} 
          disabled={page === 0 || loading}
          style={{border: '1px solid var(--border)'}}
        >
          Previous
        </button>
        <span style={{alignSelf: 'center', fontSize: '0.9rem', color: 'var(--text-light)'}}>Page {page + 1}</span>
        <button 
          onClick={() => setPage(p => p + 1)} 
          disabled={history.length < limit || loading}
          style={{border: '1px solid var(--border)'}}
        >
          Next
        </button>
      </div>
    </div>
  );
}

export default AnalysisHistory;
