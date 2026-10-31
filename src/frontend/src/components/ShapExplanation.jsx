import React from 'react';
import Plot from 'react-plotly.js';

function ShapExplanation({ explanation }) {
  if (!explanation) {
    return (
      <div className="card">
        <h3 className="mb-4">Explainable AI (SHAP) — Feature Attribution</h3>
        <p style={{ color: 'var(--text-light)' }}>SHAP explanation data is not available for this sample.</p>
      </div>
    );
  }

  // Extract feature names and values robustly across any schema format
  let featureNames = [];
  let shapValues = [];

  // Priority 1: plot_data from backend
  if (explanation.plot_data && Array.isArray(explanation.plot_data.features) && Array.isArray(explanation.plot_data.values)) {
    featureNames = [...explanation.plot_data.features];
    shapValues = [...explanation.plot_data.values];
  }
  // Priority 2: shap_values array of objects [{feature, value}] or [[name, val]]
  else if (Array.isArray(explanation.shap_values)) {
    explanation.shap_values.slice(0, 10).forEach(item => {
      if (Array.isArray(item) && item.length >= 2) {
        featureNames.push(item[0]);
        shapValues.push(Number(item[1]));
      } else if (item && typeof item === 'object') {
        featureNames.push(item.feature || item.name || Object.keys(item)[0]);
        shapValues.push(Number(item.value !== undefined ? item.value : Object.values(item)[0]));
      }
    });
  }

  // Reverse order for horizontal bar chart so highest appears at top
  const chartFeatures = [...featureNames].reverse();
  const chartValues = [...shapValues].reverse();
  const chartColors = chartValues.map(v => v >= 0 ? '#dc3545' : '#28a745');

  const formatted = explanation.formatted || {};
  const topFeaturesTable = formatted.top_features_table || [];
  const topMalicious = explanation.top_malicious_contributors || [];
  const topBenign = explanation.top_benign_contributors || [];

  return (
    <div className="card">
      <div className="flex justify-between items-center mb-4">
        <div>
          <h3 style={{ margin: 0 }}>Explainable AI (SHAP) Analysis</h3>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-light)', fontSize: '0.9rem' }}>
            TreeExplainer transparency report detailing exactly how features swayed the AI model's decision.
          </p>
        </div>
        {formatted.confidence_interpretation && (
          <span className="badge" style={{ background: '#eef2ff', color: '#4338ca', fontWeight: 600 }}>
            {formatted.confidence_interpretation}
          </span>
        )}
      </div>

      {formatted.summary && (
        <div style={{ background: '#f8fafc', padding: '12px 16px', borderRadius: '8px', borderLeft: '4px solid #3b82f6', marginBottom: '20px' }}>
          <p style={{ margin: 0, fontSize: '0.95rem', color: '#1e293b' }}>
            {formatted.summary}
          </p>
        </div>
      )}

      {/* Top Contributor Badges */}
      <div className="grid grid-2 gap-4 mb-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
        <div style={{ background: '#fff5f5', border: '1px solid #fed7d7', borderRadius: '8px', padding: '12px 16px' }}>
          <strong style={{ color: '#c53030', display: 'block', marginBottom: '8px' }}>
            🚨 Top Indicators Pushing Towards MALICIOUS (+SHAP)
          </strong>
          {topMalicious.length > 0 ? (
            <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.88rem', color: '#742a2a' }}>
              {topMalicious.slice(0, 4).map((item, idx) => (
                <li key={idx} style={{ marginBottom: '4px' }}>
                  <strong>{item.feature}</strong>: <span style={{ color: '#c53030', fontWeight: 'bold' }}>+{Number(item.value).toFixed(4)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <span style={{ fontSize: '0.85rem', color: '#718096' }}>No significant malicious indicators detected.</span>
          )}
        </div>

        <div style={{ background: '#f0fff4', border: '1px solid #c6f6d5', borderRadius: '8px', padding: '12px 16px' }}>
          <strong style={{ color: '#22543d', display: 'block', marginBottom: '8px' }}>
            🛡️ Top Indicators Pushing Towards BENIGN (-SHAP)
          </strong>
          {topBenign.length > 0 ? (
            <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.88rem', color: '#22543d' }}>
              {topBenign.slice(0, 4).map((item, idx) => (
                <li key={idx} style={{ marginBottom: '4px' }}>
                  <strong>{item.feature}</strong>: <span style={{ color: '#28a745', fontWeight: 'bold' }}>{Number(item.value).toFixed(4)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <span style={{ fontSize: '0.85rem', color: '#718096' }}>No significant benign baseline indicators detected.</span>
          )}
        </div>
      </div>

      {/* Plotly Interactive Feature Impact Chart */}
      {chartFeatures.length > 0 ? (
        <div style={{ marginBottom: '24px' }}>
          <h4 style={{ marginBottom: '12px' }}>SHAP Feature Attribution Bar Chart</h4>
          <div style={{ width: '100%', height: '380px', overflowX: 'auto' }}>
            <Plot
              data={[
                {
                  type: 'bar',
                  x: chartValues,
                  y: chartFeatures,
                  orientation: 'h',
                  marker: {
                    color: chartColors,
                  },
                  text: chartValues.map(v => `${v >= 0 ? '+' : ''}${Number(v).toFixed(4)}`),
                  textposition: 'auto',
                }
              ]}
              layout={{
                margin: { l: 200, r: 30, t: 20, b: 50 },
                xaxis: { 
                  title: 'SHAP Value Impact (← Safe/Benign | Threat/Malicious →)',
                  zeroline: true,
                  zerolinecolor: '#94a3b8',
                  zerolinewidth: 2,
                },
                yaxis: { automargin: true },
                autosize: true,
              }}
              useResizeHandler={true}
              style={{ width: '100%', height: '100%' }}
              config={{ responsive: true, displayModeBar: false }}
            />
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-light)', fontStyle: 'italic', marginTop: '6px' }}>
            * <span style={{ color: '#dc3545', fontWeight: 600 }}>Red positive values</span> increase the AI model's suspicion towards MALICIOUS. <span style={{ color: '#28a745', fontWeight: 600 }}>Green negative values</span> pull the verdict towards BENIGN / Safe.
          </p>
        </div>
      ) : (
        <p style={{ color: 'var(--text-light)', fontStyle: 'italic' }}>Feature attribution chart not available.</p>
      )}

      {/* Detailed Table of Features with Descriptions */}
      {topFeaturesTable.length > 0 && (
        <div style={{ marginTop: '20px' }}>
          <h4 style={{ marginBottom: '12px' }}>Feature Contribution Breakdown</h4>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.88rem' }}>
              <thead>
                <tr style={{ background: '#f1f5f9', textAlign: 'left', borderBottom: '2px solid #cbd5e1' }}>
                  <th style={{ padding: '10px 12px' }}>Feature Name</th>
                  <th style={{ padding: '10px 12px' }}>Impact Value</th>
                  <th style={{ padding: '10px 12px' }}>Direction</th>
                  <th style={{ padding: '10px 12px' }}>Description</th>
                </tr>
              </thead>
              <tbody>
                {topFeaturesTable.map((item, idx) => {
                  const isPos = item.contribution > 0;
                  return (
                    <tr key={idx} style={{ borderBottom: '1px solid #e2e8f0', background: idx % 2 === 0 ? '#fff' : '#f8fafc' }}>
                      <td style={{ padding: '10px 12px', fontWeight: 600, color: '#334155' }}>
                        <code>{item.feature}</code>
                      </td>
                      <td style={{ padding: '10px 12px', fontWeight: 'bold', color: isPos ? '#dc3545' : '#28a745' }}>
                        {isPos ? '+' : ''}{Number(item.contribution).toFixed(4)}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span 
                          className="badge" 
                          style={{ 
                            background: isPos ? '#fee2e2' : '#dcfce7', 
                            color: isPos ? '#991b1b' : '#166534',
                            fontSize: '0.75rem',
                            padding: '3px 8px'
                          }}
                        >
                          {isPos ? 'Threat Indicator' : 'Safe Baseline'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', color: '#64748b', fontSize: '0.85rem' }}>
                        {item.description}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {formatted.disclaimer && (
        <p style={{ fontSize: '0.78rem', color: '#94a3b8', fontStyle: 'italic', marginTop: '16px' }}>
          {formatted.disclaimer}
        </p>
      )}
    </div>
  );
}

export default ShapExplanation;
