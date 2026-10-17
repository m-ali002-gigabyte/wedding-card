const { createHmac, createHash, timingSafeEqual, randomBytes } = require('node:crypto');

// These details stay on the server. Guests receive only their permitted events.
const EVENTS = {
  mehndi: { key: 'mehndi', title: 'Rasm-e-Hina', urdu: 'رسمِ حنا', date: 'Friday, 30 October 2026', time: '7:00 PM – 9:00 PM' },
  barat: { key: 'barat', title: 'Barat', urdu: 'بارات', date: 'Saturday, 31 October 2026', time: 'Sehra Bandi: 10:00 AM · Departure: 12:00 PM' },
  walima: { key: 'walima', title: 'Walima', urdu: 'ولیمہ', date: 'Sunday, 1 November 2026', time: '1:00 PM – 3:00 PM' }
};
const MODES = {
  mehndi: ['mehndi'], barat: ['barat'], walima: ['walima'],
  'mehndi-walima': ['mehndi', 'walima'],
  'barat-walima': ['barat', 'walima'], all: ['mehndi', 'barat', 'walima']
};
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const equal = (a, b) => timingSafeEqual(createHash('sha256').update(a).digest(), createHash('sha256').update(b).digest());
const signature = (data, secret) => createHmac('sha256', secret).update(data).digest('base64url');
const details = keys => ({
  events: keys.map(key => ({
    ...EVENTS[key],
    ...(key === 'barat' ? {} : {
      venue: 'IQBAL PALACE', address: 'Dhamial Road, Rawalpindi'
    })
  }))
});

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const secret = process.env.INVITE_SECRET || '';
  const password = process.env.HOST_PASSWORD || '';
  if (secret.length < 32 || password.length < 16) {
    return res.status(503).json({ error: 'Host setup incomplete: add HOST_PASSWORD (16+ characters) and INVITE_SECRET (32+ characters) in Vercel, then redeploy.' });
  }
  const auth = req.headers.authorization;
  const bearer = typeof auth === 'string' && auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (req.method === 'POST') {
    if (!bearer || bearer.length > 1024 || !equal(bearer, password)) return res.status(401).json({ error: 'Incorrect host password.' });
    let body = req.body;
    try { if (typeof body === 'string') body = JSON.parse(body); }
    catch { return res.status(400).json({ error: 'Invalid request.' }); }
    if (!body || typeof body !== 'object') return res.status(400).json({ error: 'Invalid request.' });
    if (body.action === 'preview') return res.status(200).json(details(MODES.all));
    if (body.action !== 'issue' || typeof body.mode !== 'string' || !own(MODES, body.mode)) {
      return res.status(400).json({ error: 'Choose a valid invitation.' });
    }
    const payload = Buffer.from(JSON.stringify({
      v: 1, events: MODES[body.mode],
      exp: Math.floor(Date.now() / 1000) + 90 * 86400,
      nonce: randomBytes(16).toString('base64url')
    })).toString('base64url');
    return res.status(200).json({ token: `${payload}.${signature(payload, secret)}` });
  }
  if (req.method === 'GET') {
    try {
      if (!bearer || bearer.length > 2048) throw new Error();
      const parts = bearer.split('.');
      if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) throw new Error();
      if (!equal(parts[1], signature(parts[0], secret))) throw new Error();
      const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      if (data.v !== 1 || !Number.isSafeInteger(data.exp) || data.exp <= Date.now() / 1000 ||
          !Array.isArray(data.events) || !data.events.length || data.events.length > 3 ||
          new Set(data.events).size !== data.events.length ||
          data.events.some(key => typeof key !== 'string' || !own(EVENTS, key))) throw new Error();
      return res.status(200).json(details(data.events));
    } catch {
      return res.status(403).json({ error: 'This invitation link is invalid or has expired. Please contact the host.' });
    }
  }
  res.setHeader('Allow', 'GET, POST');
  return res.status(405).json({ error: 'Method not allowed.' });
};

