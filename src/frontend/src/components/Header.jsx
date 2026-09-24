import React from 'react';

function Header({ currentView, onNavigate }) {
  return (
    <header className="header-bar">
      <div className="container header-content">
        <div className="header-title">
          <h1>🛡️ XMalGuard</h1>
          <p>AI-Powered Static Malware Analysis</p>
        </div>
        <nav className="header-nav">
          <button 
            className={currentView === 'upload' ? 'active' : ''} 
            onClick={() => onNavigate('upload')}
          >
            New Analysis
          </button>
          <button 
            className={currentView === 'history' ? 'active' : ''} 
            onClick={() => onNavigate('history')}
          >
            History
          </button>
        </nav>
      </div>
    </header>
  );
}

export default Header;
