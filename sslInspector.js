const tls = require('tls');

function inspectSSL(host, port = 443, timeout = 5000) {
  return new Promise((resolve) => {
    const result = { host, port, ok: false, subject: null, issuer: null, notBefore: null, notAfter: null, expired: false };
    try {
      const socket = tls.connect({ host, port, servername: host, timeout }, () => {
        const cert = socket.getPeerCertificate(true);
        if (!cert || Object.keys(cert).length === 0) {
          result.error = 'no certificate returned';
          resolve(result);
          socket.end();
          return;
        }
        result.ok = true;
        result.subject = cert.subject;
        result.issuer = cert.issuer;
        result.notBefore = cert.valid_from;
        result.notAfter = cert.valid_to;
        // simple expiry check
        try {
          const now = new Date();
          const notAfter = new Date(cert.valid_to);
          result.expired = notAfter < now;
        } catch (e) {}
        resolve(result);
        socket.end();
      });
      socket.on('error', (err) => {
        result.error = err.message;
        resolve(result);
      });
    } catch (e) {
      result.error = e.message;
      resolve(result);
    }
  });
}

module.exports = { inspectSSL };
