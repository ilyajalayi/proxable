// server.js
import express from 'express';
import rateLimit from 'express-rate-limit';
import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';
import { URL } from 'url';

const PORT = process.env.PORT ? Number(process.env.PORT) : 8080;
const PROXY_KEY = process.env.PROXY_KEY || ''; // you should set Key in ENV 
if (!PROXY_KEY) {
  console.warn('Warning: PROXY_KEY not set. Set env var PROXY_KEY for security.');
}

const app = express();
app.use(express.raw({ type: '*/*', limit: '10mb' })); // raw body passthrough

// simple ratelimiter
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // max requests per IP per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// middleware auth
function checkAuth(req, res, next) {
  const key = req.header('x-proxy-key') || req.query.proxy_key;
  if (!PROXY_KEY) return res.status(403).json({ error: 'PROXY_KEY not configured on server' });
  if (!key || key !== PROXY_KEY) {
    return res.status(401).json({ error: 'Unauthorized. Provide x-proxy-key header or ?proxy_key=' });
  }
  next();
}

// Utility: build headers to forward (skip hop-by-hop)
const HOP_BY_HOP = new Set([
  'connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailers','transfer-encoding','upgrade','host'
]);

function buildForwardHeaders(incomingHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(incomingHeaders)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    // don't forward proxy auth header
    if (lk === 'x-proxy-key') continue;
    out[k] = v;
  }
  // Ensure a user-agent
  if (!out['user-agent'] && !out['User-Agent']) {
    out['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115 Safari/537.36';
  }
  return out;
}

// -------- HTTP(S) proxy endpoint --------
// Usage:
// GET /proxy?link=<full-target-url>
// Accepts any method; body will be forwarded.
app.all('/proxy', checkAuth, async (req, res) => {
  const linkRaw = req.query.link;
  if (!linkRaw) {
    return res.status(400).json({ error: "Missing 'link' query param. Example: /proxy?link=https://api.binance.com/..." });
  }

  // decode (in case client double-encoded)
  let target;
  try {
    target = decodeURIComponent(String(linkRaw));
  } catch (e) {
    target = String(linkRaw);
  }

  // validate URL
  let targetUrl;
  try {
    targetUrl = new URL(target);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid target URL' });
  }

  // build fetch options
  const method = req.method;
  const headers = buildForwardHeaders(req.headers);
  // remove accept-encoding to allow Node to handle compression
  delete headers['accept-encoding'];

  const fetchOptions = {
    method,
    headers,
    // body: only include for methods that have body
    body: ['POST','PUT','PATCH','DELETE'].includes(method) ? req.body : undefined,
    // keep redirect manual so we can pass response code back
    redirect: 'manual'
  };

  try {
    const upstream = await fetch(targetUrl.toString(), fetchOptions);
    // forward status
    res.status(upstream.status);
    // forward headers (skip hop-by-hop)
    upstream.headers.forEach((value, key) => {
      if (HOP_BY_HOP.has(key)) return;
      if (key === 'content-encoding') return; // prevent double-compression issues
      res.setHeader(key, value);
    });

    // stream body
    const reader = upstream.body?.getReader();
    if (!reader) {
      // fallback - buffer
      const buf = await upstream.arrayBuffer();
      res.send(Buffer.from(buf));
      return;
    }

    // stream chunks
    res.flushHeaders();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
    }
    res.end();
  } catch (err) {
    console.error('Upstream fetch error:', err.message || err);
    return res.status(502).json({ error: 'Upstream fetch failed', detail: String(err.message || err) });
  }
});

// -------- WebSocket proxy --------
// We create an HTTP server and attach a WebSocket server to handle upgrades.
// Client connects to ws://our-host/ws?target=<wss://stream.binance.com:9443/ws/xxx>&proxy_key=...
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 10 * 1024 * 1024 }); // 10MB

server.on('upgrade', (request, socket, head) => {
  const parsed = new URL(request.url, `http://${request.headers.host}`);
  if (!parsed.pathname.startsWith('/ws')) {
    socket.destroy();
    return;
  }
  const targetRaw = parsed.searchParams.get('target');
  const providedKey = request.headers['x-proxy-key'] || parsed.searchParams.get('proxy_key');
  if (!PROXY_KEY) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }
  if (providedKey !== PROXY_KEY) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy();
    return;
  }
  if (!targetRaw) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  let targetUrl;
  try {
    targetUrl = decodeURIComponent(targetRaw);
  } catch (e) {
    targetUrl = targetRaw;
  }

  // Accept client's websocket connection
  wss.handleUpgrade(request, socket, head, (clientWs) => {
    // create upstream websocket to target
    const upstreamWs = new WebSocket(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115 Safari/537.36',
        'Origin': 'https://www.binance.com'
      }
    });

    // pipe messages both ways
    upstreamWs.on('open', () => {
      // forward client -> upstream
      clientWs.on('message', (msg) => {
        try { upstreamWs.send(msg); } catch (e) {}
      });
      clientWs.on('close', () => { try { upstreamWs.close(); } catch (e) {} });
      clientWs.on('error', () => { try { upstreamWs.close(); } catch (e) {} });

      // forward upstream -> client
      upstreamWs.on('message', (msg) => {
        try { clientWs.send(msg); } catch (e) {}
      });
      upstreamWs.on('close', () => { try { clientWs.close(); } catch (e) {} });
      upstreamWs.on('error', (e) => {
        console.error('Upstream WS error', e);
        try { clientWs.close(); } catch (e) {}
      });
    });

    upstreamWs.on('error', (err) => {
      console.error('Failed to connect upstream websocket:', err.message || err);
      try { clientWs.close(); } catch (e) {}
    });
  });
});

server.listen(PORT, () => {
  console.log(`Proxy server listening on port ${PORT}`);
  console.log(`HTTP proxy: GET/POST /proxy?link=<url> with x-proxy-key header`);
  console.log(`WS proxy: ws://host/ws?target=<wss://...>&proxy_key=YOUR_KEY`);
});
//Made on a happy day by ilya
