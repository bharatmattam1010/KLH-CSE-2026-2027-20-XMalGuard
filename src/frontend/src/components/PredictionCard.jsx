import React from 'react';

function PredictionCard({ prediction }) {
  if (!prediction) return null;

  let isMalicious = false;
  if (prediction.is_malicious === true) isMalicious = true;
  if (typeof prediction.prediction === 'string' && prediction.prediction.toLowerCase() === 'malicious') isMalicious = true;
  if (typeof prediction === 'string' && prediction.toLowerCase() === 'malicious') isMalicious = true;

  const label = isMalicious ? 'MALICIOUS' : 'BENIGN';
  const confidence = (Number(prediction.confidence || 0) * 100).toFixed(1);
  
  const malProb = prediction.probabilities?.malicious !== undefined 
    ? prediction.probabilities.malicious 
    : (prediction.malicious_probability !== undefined ? prediction.malicious_probability : (isMalicious ? prediction.confidence : 1 - prediction.confidence));
    
  const benProb = prediction.probabilities?.benign !== undefined 
    ? prediction.probabilities.benign 
    : (prediction.benign_probability !== undefined ? prediction.benign_probability : (isMalicious ? 1 - prediction.confidence : prediction.confidence));

  const bgColor = isMalicious ? 'var(--critical)' : 'var(--success)';
  const textColor = 'white';

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', backgroundColor: bgColor, color: textColor }}>
      <h3 style={{ textTransform: 'uppercase', letterSpacing: '2px', opacity: 0.9, margin: 0 }}>Verdict</h3>
      <div style={{ fontSize: '3rem', fontWeight: 'bold', margin: '16px 0' }}>{label}</div>
      <div style={{ width: '100%', maxWidth: '300px', backgroundColor: 'rgba(255,255,255,0.2)', borderRadius: '8px', height: '12px', overflow: 'hidden', margin: '8px 0' }}>
        <div style={{ width: `${Math.min(100, Math.max(0, confidence))}%`, backgroundColor: 'white', height: '100%' }}></div>
      </div>
      <p style={{ fontSize: '1.2rem', fontWeight: '500' }}>{confidence}% Confidence</p>
      <div style={{ display: 'flex', gap: '16px', marginTop: '16px', fontSize: '0.9rem', opacity: 0.9 }}>
        <span>Malicious Probability: {(Number(malProb || 0) * 100).toFixed(1)}%</span>
        <span>Benign Probability: {(Number(benProb || 0) * 100).toFixed(1)}%</span>
      </div>
    </div>
  );
}

export default PredictionCard;
