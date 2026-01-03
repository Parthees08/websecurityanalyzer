const axios = require('axios');
const { JSDOM } = require('jsdom');

async function inspectHttp(target) {
  const result = { url: target, ok: false, status: null, headers: {}, missingHeaders: [], externalScripts: [], forms: [] };
  try {
    const r = await axios.get(target, { timeout: 8000, maxRedirects: 5, headers: { 'User-Agent': 'WebSecAnalyzer/1.0' } });
    result.ok = true;
    result.status = r.status;
    result.headers = r.headers;

    const checkList = ['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options','referrer-policy'];
    checkList.forEach(h => { if (!r.headers[h]) result.missingHeaders.push(h); });

    // parse HTML for scripts/forms
    if (r.headers['content-type'] && r.headers['content-type'].includes('text/html')) {
      const dom = new JSDOM(r.data);
      const document = dom.window.document;
      const scripts = Array.from(document.querySelectorAll('script')).map(s => s.src).filter(Boolean);
      result.externalScripts = scripts.slice(0,20);
      const forms = Array.from(document.querySelectorAll('form')).map(f => ({ action: f.action, method: f.method || 'get' }));
      result.forms = forms.slice(0,20);
    }
  } catch (e) {
    result.error = e.message;
  }
  return result;
}

module.exports = { inspectHttp };
