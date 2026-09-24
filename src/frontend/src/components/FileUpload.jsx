import React, { useState, useRef } from 'react';
import { api } from '../services/api';

function FileUpload({ onAnalysisComplete, onBatchAnalysisComplete }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    validateAndSetFile(selected);
  };

  const validateAndSetFile = (selected) => {
    setError('');
    if (!selected) return;

    if (!selected.name.match(/\.(exe|dll|zip)$/i)) {
      setError('Invalid file type. Please upload an .exe, .dll, or .zip dataset file.');
      return;
    }

    if (selected.size > 10000 * 1024 * 1024) {
      setError('File is too large. Maximum size is 10GB.');
      return;
    }

    setFile(selected);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;
    setLoading(true);
    setError('');

    try {
      if (file.name.match(/\.zip$/i)) {
        const result = await api.analyzeBatch(file);
        if (onBatchAnalysisComplete) {
            onBatchAnalysisComplete(result);
        }
      } else {
        const result = await api.analyzeFile(file);
        onAnalysisComplete(result);
      }
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'An error occurred during analysis. Make sure the backend API is running.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2 className="mb-4">Upload File or Dataset for Analysis</h2>
      
      {error && <div className="alert-error">{error}</div>}

      <div 
        className={`upload-area ${isDragOver ? 'dragover' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <div className="flex flex-col items-center gap-4">
          <span style={{fontSize: '3rem'}}>📁</span>
          <h3>Drag and drop your file here</h3>
          <p className="text-light">or</p>
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange} 
            style={{display: 'none'}} 
            accept=".exe,.dll,.zip"
          />
          <button 
            className="btn-primary" 
            onClick={() => fileInputRef.current.click()}
            disabled={loading}
          >
            Browse Files
          </button>
          <p style={{fontSize: '0.85em', color: 'var(--text-light)'}}>Supported formats: .exe, .dll, or .zip (Max 10GB)</p>
        </div>
      </div>

      {file && (
        <div className="mt-4 flex items-center justify-between" style={{background: '#f8f9fa', padding: '16px', borderRadius: '8px'}}>
          <div>
            <strong>Selected File: </strong> {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
            {file.name.match(/\.zip$/i) && <span style={{display: 'block', color: 'var(--primary-color)', fontSize: '0.9em', marginTop: '4px'}}>dataset upload detected.</span>}
          </div>
          <button 
            className="btn-primary" 
            onClick={handleAnalyze} 
            disabled={loading}
          >
            {loading ? 'Analyzing... This may take a moment.' : 'Analyze'}
          </button>
        </div>
      )}
    </div>
  );
}

export default FileUpload;
