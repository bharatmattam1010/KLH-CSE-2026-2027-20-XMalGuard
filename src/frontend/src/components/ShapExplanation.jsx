import React from 'react';
import Plot from 'react-plotly.js';

function ShapExplanation({ explanation }) {
  // Extract data from the [name, value] tuple array
  let featureNames = [];
  let shapValues = [];
  
  if (explanation && explanation.shap_values && Array.isArray(explanation.shap_values)) {
    // Top 10 only
    explanation.shap_values.slice(0, 10).forEach(item => {
      if (Array.isArray(item) && item.length === 2) {
        featureNames.push(item[0]);
        shapValues.push(item[1]);
      }
    });
  }

  return (
    <div className="card">
      <h3 className="mb-4">Explainable AI — Feature Contributions</h3>
      
      {featureNames.length === 0 ? (
        <p style={{color: 'var(--text-light)'}}>SHAP explanation not available for this analysis.</p>
      ) : (
        <div>
          <div style={{ width: '100%', height: '400px', overflowX: 'auto' }}>
            <Plot
              data={[
                {
                  type: 'bar',
                  x: shapValues,
                  y: featureNames,
                  orientation: 'h',
                  marker: {
                    color: shapValues.map(v => v >= 0 ? '#dc3545' : '#0f3460')
                  }
                }
              ]}
              layout={{
                title: 'Top 10 Feature Contributions',
                margin: { l: 150, r: 20, t: 40, b: 40 },
                xaxis: { title: 'SHAP Value (impact on model output)' },
                yaxis: { automargin: true }
              }}
              useResizeHandler={true}
              style={{ width: '100%', height: '100%' }}
            />
          </div>
          
          <div className="mt-4">
            <table style={{fontSize: '0.9rem'}}>
              <thead>
                <tr>
                  <th>Feature Name</th>
                  <th>Contribution</th>
                </tr>
              </thead>
              <tbody>
                {featureNames.map((name, idx) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td style={{color: shapValues[idx] >= 0 ? 'var(--danger)' : 'var(--accent)', fontWeight: 'bold'}}>
                      {shapValues[idx] > 0 ? '+' : ''}{shapValues[idx]?.toFixed(4)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p style={{fontSize: '0.8rem', color: 'var(--text-light)', fontStyle: 'italic', marginTop: '16px'}}>
            * Red/Positive values push the model toward MALICIOUS. Blue/Negative values push the model toward BENIGN.
          </p>
        </div>
      )}
    </div>
  );
}

export default ShapExplanation;
