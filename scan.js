const express = require('express');
const router = express.Router();
const { inspectHttp } = require('../utils/httpInspector');
const { inspectSSL } = require('../utils/sslInspector');
const { probeVulns } = require('../utils/vulnProber');
const url = require('url');

router.post('/scan', async (req, res) => {
  const target = req.body.url;
  if (!target) return res.status(400).json({ error: 'url is required' });
  try {
    const parsed = url.parse(target);
    const host = parsed.hostname;
    const httpRes = await inspectHttp(target);
    const sslRes = await inspectSSL(host, 443);
    const vulns = await probeVulns(target);
    const score = computeScore(httpRes, sslRes, vulns);
    return res.json({ url: target, score, http: httpRes, ssl: sslRes, vulns });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message });
  }
});

function computeScore(httpRes, sslRes, vulns) {
  let score = 100;
  if (httpRes.missingHeaders && httpRes.missingHeaders.length) {
    score -= 5 * httpRes.missingHeaders.length;
  }
  if (sslRes.error) score -= 30;
  if (sslRes.expired) score -= 40;
  vulns.forEach(v => {
    if (v.type === 'reflected_xss') score -= 35;
    else if (v.type === 'sqli_error') score -= 40;
    else if (v.type === 'directory_listing') score -= 20;
    else score -= 5;
  });
  if (score < 0) score = 0;
  return score;
}

module.exports = router;
