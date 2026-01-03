import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [url, setUrl] = useState('https://example.com');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const runScan = async () => {
    setLoading(true); setResult(null); setError(null);
    try {
      const res = await axios.post('http://localhost:5000/api/scan', { url });
      setResult(res.data);
    } catch (e) {
      setError(e.response && e.response.data ? JSON.stringify(e.response.data) : e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header><h1>Web Security Analyzer</h1></header>
      <main>
        <div className="form">
          <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" />
          <button onClick={runScan} disabled={loading}>Scan</button>
        </div>
        {loading && <p>Scanning...</p>}
        {error && <pre className="error">{error}</pre>}
        {result && <div className="result"><h2>Score: {result.score}</h2><pre>{JSON.stringify(result, null, 2)}</pre></div>}
      </main>
    </div>
  );
}

export default App;
