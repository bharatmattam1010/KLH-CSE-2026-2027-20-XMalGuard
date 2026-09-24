import React, { useState } from 'react';

function StaticFeatures({ features }) {
  if (!features) return null;

  const [expanded, setExpanded] = useState({
    header: true,
    sections: false,
    imports: false,
    strings: false
  });

  const toggle = (section) => {
    setExpanded(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const ml = features.ml_features || {};
  const display = features.display_info || {};

  return (
    <div className="card">
      <h3 className="mb-4">Static Analysis Features</h3>
      
      {/* PE Header */}
      <div style={{marginBottom: '16px', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden'}}>
        <div 
          style={{padding: '12px 16px', backgroundColor: '#f8f9fa', cursor: 'pointer', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between'}}
          onClick={() => toggle('header')}
        >
          <span>PE Header Details</span>
          <span>{expanded.header ? '▼' : '▶'}</span>
        </div>
        {expanded.header && ml && (
          <div style={{padding: '16px'}}>
            <table style={{fontSize: '0.9rem'}}>
              <tbody>
                <tr><td style={{fontWeight: '500'}}>Machine Type</td><td>{ml.machine_type}</td></tr>
                <tr><td style={{fontWeight: '500'}}>Subsystem</td><td>{ml.subsystem}</td></tr>
                <tr><td style={{fontWeight: '500'}}>Image Base</td><td>{ml.image_base}</td></tr>
                <tr><td style={{fontWeight: '500'}}>Entry Point</td><td>{ml.entry_point}</td></tr>
                <tr><td style={{fontWeight: '500'}}>Characteristics</td><td>{ml.characteristics}</td></tr>
                <tr><td style={{fontWeight: '500'}}>Size of Image</td><td>{ml.size_of_image}</td></tr>
                <tr><td style={{fontWeight: '500'}}>File Entropy</td><td>{ml.file_entropy?.toFixed(4)}</td></tr>
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Sections */}
      <div style={{marginBottom: '16px', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden'}}>
        <div 
          style={{padding: '12px 16px', backgroundColor: '#f8f9fa', cursor: 'pointer', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between'}}
          onClick={() => toggle('sections')}
        >
          <span>PE Sections ({display.section_details?.length || 0})</span>
          <span>{expanded.sections ? '▼' : '▶'}</span>
        </div>
        {expanded.sections && display.section_details && (
          <div style={{padding: '16px', overflowX: 'auto'}}>
            <table style={{fontSize: '0.9rem', width: '100%', minWidth: '500px'}}>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Virtual Size</th>
                  <th>Raw Size</th>
                  <th>Entropy</th>
                </tr>
              </thead>
              <tbody>
                {display.section_details.map((sec, i) => (
                  <tr key={i}>
                    <td>{sec.name}</td>
                    <td>{sec.virtual_size}</td>
                    <td>{sec.size_of_raw_data}</td>
                    <td>{sec.entropy?.toFixed(4)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Imports */}
      <div style={{marginBottom: '16px', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden'}}>
        <div 
          style={{padding: '12px 16px', backgroundColor: '#f8f9fa', cursor: 'pointer', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between'}}
          onClick={() => toggle('imports')}
        >
          <span>Imported DLLs ({display.imported_dlls?.length || 0})</span>
          <span>{expanded.imports ? '▼' : '▶'}</span>
        </div>
        {expanded.imports && display.imported_dlls && (
          <div style={{padding: '16px'}}>
            {display.imported_dlls.map((imp, i) => (
              <div key={i} style={{marginBottom: '12px'}}>
                <h5 style={{marginBottom: '4px'}}>{imp.dll} ({imp.functions?.length || 0} functions)</h5>
                <p style={{fontSize: '0.85rem', color: 'var(--text-light)', margin: 0}}>
                  {imp.functions?.slice(0, 10).join(', ')}
                  {imp.functions?.length > 10 ? ' ...' : ''}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Strings */}
      <div style={{marginBottom: '16px', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden'}}>
        <div 
          style={{padding: '12px 16px', backgroundColor: '#f8f9fa', cursor: 'pointer', fontWeight: 'bold', display: 'flex', justifyContent: 'space-between'}}
          onClick={() => toggle('strings')}
        >
          <span>Strings Analysis</span>
          <span>{expanded.strings ? '▼' : '▶'}</span>
        </div>
        {expanded.strings && ml && (
          <div style={{padding: '16px'}}>
            <table style={{fontSize: '0.9rem'}}>
              <tbody>
                <tr>
                  <td style={{fontWeight: '500'}}>Total Strings Found</td>
                  <td>{ml.printable_string_count || 0}</td>
                </tr>
                <tr>
                  <td style={{fontWeight: '500'}}>Suspicious Strings</td>
                  <td>{ml.suspicious_string_count || 0}</td>
                </tr>
                <tr>
                  <td style={{fontWeight: '500'}}>Found Anomalies</td>
                  <td>{display.suspicious_strings_found?.slice(0,10).join(', ') || "None"}</td>
                </tr>
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}

export default StaticFeatures;
