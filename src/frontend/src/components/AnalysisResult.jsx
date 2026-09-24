import React from 'react';
import FileInfo from './FileInfo';
import PredictionCard from './PredictionCard';
import RiskAssessment from './RiskAssessment';
import StaticFeatures from './StaticFeatures';
import ShapExplanation from './ShapExplanation';
import ThreatIntelligence from './ThreatIntelligence';
import { api } from '../services/api';

function AnalysisResult({ result, onNewAnalysis, onBack }) {
  if (!result) return <div>No result data available.</div>;

  const handleDownloadReport = async () => {
    try {
      const blob = await api.getReport(result.id || result.analysis_id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${result.filename}.html`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download report", err);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex justify-between items-center mb-2">
        <h2>Analysis Results</h2>
        <div className="flex gap-4">
          {onBack && <button onClick={onBack} style={{border: '1px solid var(--border)'}}>← Back</button>}
          <button className="btn-primary" onClick={handleDownloadReport}>Download Report</button>
          <button onClick={onNewAnalysis} style={{border: '1px solid var(--border)'}}>New Analysis</button>
        </div>
      </div>

      <div className="grid grid-cols-2">
        <PredictionCard prediction={result.prediction} />
        <RiskAssessment assessment={result.risk_assessment} />
      </div>

      <FileInfo info={result.file_info} />
      
      <ThreatIntelligence threatIntel={result.threat_intelligence} />
      
      <StaticFeatures features={result.static_features} />
      
      <ShapExplanation explanation={result.explanation} />
    </div>
  );
}

export default AnalysisResult;
