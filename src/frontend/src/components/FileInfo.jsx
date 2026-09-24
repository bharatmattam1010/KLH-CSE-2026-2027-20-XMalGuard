import React from 'react';

function FileInfo({ info }) {
  if (!info) return null;

  const getArchName = (machine) => {
    if (machine === 332) return 'x86 (32-bit)';
    if (machine === 34404) return 'x64 (64-bit)';
    return `Unknown (${machine})`;
  };

  return (
    <div className="card">
      <h3 className="mb-4">File Information</h3>
      <div className="grid grid-cols-2">
        <div>
          <p><strong>Filename:</strong> {info.filename}</p>
          <p><strong>Size:</strong> {(info.size / 1024).toFixed(2)} KB</p>
          <p><strong>Architecture:</strong> {getArchName(info.pe_info?.machine)}</p>
          <p><strong>Subsystem:</strong> {info.pe_info?.subsystem}</p>
          <p><strong>Sections:</strong> {info.pe_info?.number_of_sections}</p>
        </div>
        <div>
          <p><strong>MD5:</strong> <br/><span style={{fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all'}}>{info.hashes?.md5}</span></p>
          <p><strong>SHA-1:</strong> <br/><span style={{fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all'}}>{info.hashes?.sha1}</span></p>
          <p><strong>SHA-256:</strong> <br/><span style={{fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all'}}>{info.hashes?.sha256}</span></p>
        </div>
      </div>
    </div>
  );
}

export default FileInfo;
