import React, { useState } from 'react';
import Header from './components/Header';
import FileUpload from './components/FileUpload';
import AnalysisResult from './components/AnalysisResult';
import AnalysisHistory from './components/AnalysisHistory';
import BatchDashboard from './components/BatchDashboard';

function App() {
  const [currentView, setCurrentView] = useState('upload'); // 'upload' | 'result' | 'history' | 'batch_result'
  const [previousView, setPreviousView] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [batchResult, setBatchResult] = useState(null);

  const handleNavigate = (view) => {
    setCurrentView(view);
  };

  const handleAnalysisComplete = (result, sourceView = null) => {
    setPreviousView(sourceView);
    setAnalysisResult(result);
    setCurrentView('result');
  };

  const handleBatchAnalysisComplete = (result) => {
    setBatchResult(result);
    setCurrentView('batch_result');
  };

  const handleViewAnalysisDetails = async (id) => {
    try {
      const { api } = await import('./services/api');
      const result = await api.getAnalysis(id);
      handleAnalysisComplete(result, currentView); // Pass currentView as previous
    } catch (err) {
      console.error("Failed to load analysis details", err);
    }
  };

  return (
    <div className="app-container">
      <Header currentView={currentView} onNavigate={handleNavigate} />
      <main className="container mt-4">
        {currentView === 'upload' && (
          <FileUpload 
            onAnalysisComplete={(res) => handleAnalysisComplete(res, null)} 
            onBatchAnalysisComplete={handleBatchAnalysisComplete}
          />
        )}
        {currentView === 'result' && (
          <AnalysisResult 
            result={analysisResult} 
            onNewAnalysis={() => setCurrentView('upload')} 
            onBack={previousView ? () => setCurrentView(previousView) : null}
          />
        )}
        {currentView === 'batch_result' && (
          <BatchDashboard 
            batchResult={batchResult} 
            onNewAnalysis={() => setCurrentView('upload')} 
            onViewDetails={handleViewAnalysisDetails}
          />
        )}
        {currentView === 'history' && (
          <AnalysisHistory onViewAnalysis={(res) => handleAnalysisComplete(res, 'history')} />
        )}
      </main>
    </div>
  );
}

export default App;
