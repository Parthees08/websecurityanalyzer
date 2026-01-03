const axios = require('axios');
const url = require('url');

const ERROR_SIGNATURES = ['SQL syntax','mysql','syntax error','ORA-','unterminated string','mysqli'];

async function probeVulns(target) {
  const findings = [];
  try {
    const parsed = url.parse(target, true);
    const qs = parsed.query || {};
    // Reflected XSS check (simple)
    const XSS_TEST = '<script>/*xss*/</script>';
    const params = Object.keys(qs);
    for (let i=0;i<Math.min(5,params.length);i++) {
      const p = params[i];
      const copy = Object.assign({}, qs);
      copy[p] = XSS_TEST;
      const qstr = new URLSearchParams(copy).toString();
      const testUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${qstr}`;
      try {
        const r = await axios.get(testUrl, { timeout: 5000 });
        if (typeof r.data === 'string' && r.data.includes(XSS_TEST)) {
          findings.push({ type: 'reflected_xss', param: p, evidence: testUrl });
          break;
        }
      } catch (e) {}
    }

    // SQLi error-based check
    for (let i=0;i<Math.min(5,params.length);i++) {
      const p = params[i];
      const copy = Object.assign({}, qs);
      copy[p] = (copy[p] || '') + "'";
      const qstr = new URLSearchParams(copy).toString();
      const testUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}?${qstr}`;
      try {
        const r = await axios.get(testUrl, { timeout: 5000 });
        const text = (typeof r.data === 'string') ? r.data.toLowerCase() : '';
        for (const sig of ERROR_SIGNATURES) {
          if (text.includes(sig.toLowerCase())) {
            findings.push({ type: 'sqli_error', param: p, signature: sig, evidence: testUrl });
            break;
          }
        }
      } catch (e) {}
    }

    // Directory listing check
    const baseUrl = `${parsed.protocol}//${parsed.host}`;
    const common = ['/.git/','/backup/','/.env','/admin/'];
    for (const c of common) {
      try {
        const r = await axios.get(baseUrl + c, { timeout: 5000, validateStatus: () => true });
        if (r.status === 200 || r.status === 403) {
          const text = (typeof r.data === 'string') ? r.data.toLowerCase() : '';
          if (text.includes('index of') || r.headers['content-type'] && r.headers['content-type'].includes('text/html')) {
            findings.push({ type: 'directory_listing', path: c, status: r.status });
          }
        }
      } catch (e) {}
    }

  } catch (e) {
    findings.push({ error: e.message });
  }
  return findings;
}

module.exports = { probeVulns };
