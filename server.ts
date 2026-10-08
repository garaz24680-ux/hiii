import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import { xor } from './src/uv/codecs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Comprehensive ad, tracker, and telemetry patterns for Vortex Security Shield
  const TRACKER_PATTERNS = [
    /google-analytics\.com/i,
    /googletagmanager\.com/i,
    /doubleclick\.net/i,
    /facebook\.net\/en_US\/fbevents\.js/i,
    /connect\.facebook\.net/i,
    /criteo\.net/i,
    /adservice\.google\./i,
    /amazon-adsystem\.com/i,
    /taboola\.com/i,
    /outbrain\.com/i,
    /scorecardresearch\.com/i,
    /hotjar\.com/i,
    /clarity\.ms/i,
    /ads-twitter\.com/i,
    /adnxs\.com/i,
    /pagead2\.googlesyndication\.com/i,
    /adroll\.com/i,
    /quantserve\.com/i,
    /pubmatic\.com/i,
    /rubiconproject\.com/i,
    /analytics\.tiktok\.com/i,
    /ads\.yahoo\.com/i,
  ];

  // Helper to extract metadata (title, favicon)
  app.get('/api/metadata', async (req, res) => {
    let rawUrl = req.query.url as string;
    if (!rawUrl) {
      return res.status(400).json({ error: 'Missing url parameter' });
    }

    if (rawUrl.startsWith('/service/')) {
      rawUrl = xor.decode(rawUrl.slice('/service/'.length));
    }

    try {
      const parsedUrl = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(parsedUrl.href, {
        signal: controller.signal,
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
          Accept:
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });
      clearTimeout(timeout);

      const html = await response.text();

      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : parsedUrl.hostname;

      let favicon = '';
      const iconMatch = html.match(
        /<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']/i
      );
      if (iconMatch && iconMatch[1]) {
        try {
          favicon = new URL(iconMatch[1], parsedUrl.origin).href;
        } catch {
          favicon = `https://www.google.com/s2/favicons?domain=${parsedUrl.hostname}&sz=64`;
        }
      } else {
        favicon = `https://www.google.com/s2/favicons?domain=${parsedUrl.hostname}&sz=64`;
      }

      res.json({
        title,
        favicon,
        url: response.url || parsedUrl.href,
        status: response.status,
      });
    } catch (err: any) {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      res.json({
        title: parsed.hostname,
        favicon: `https://www.google.com/s2/favicons?domain=${parsed.hostname}&sz=64`,
        url: rawUrl,
        error: err.message,
      });
    }
  });

  // Proxy handler used by both /service/:encodedUrl (Ultraviolet) and /api/proxy
  const handleProxyRequest = async (
    rawUrl: string,
    shieldEnabled: boolean,
    req: express.Request,
    res: express.Response
  ) => {
    let targetUrl: URL;
    try {
      targetUrl = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
    } catch {
      return res.status(400).send('Invalid URL format');
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 12000);

      // Standard desktop Chrome headers for seamless compatibility with Google, DuckDuckGo, Bing
      const fetchHeaders: Record<string, string> = {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      };

      if (shieldEnabled) {
        fetchHeaders['DNT'] = '1';
        fetchHeaders['Sec-GPC'] = '1';
      }

      const fetchOptions: RequestInit = {
        signal: controller.signal,
        headers: fetchHeaders,
        redirect: 'follow',
        method: req.method === 'POST' ? 'POST' : 'GET',
      };

      // Handle POST bodies (e.g. search forms)
      if (req.method === 'POST') {
        const contentType = req.headers['content-type'] || 'application/x-www-form-urlencoded';
        fetchHeaders['Content-Type'] = contentType as string;
        if (typeof req.body === 'object') {
          fetchOptions.body = new URLSearchParams(req.body).toString();
        } else if (typeof req.body === 'string') {
          fetchOptions.body = req.body;
        }
      }

      let response = await fetch(targetUrl.href, fetchOptions);
      clearTimeout(timeout);

      // Deliver Brave Search: Brave returns 429 for cloud data center IPs while still
      // including the full SvelteKit Brave Search application body. We serve it with status 200
      // so the browser renders the genuine Brave Search engine smoothly.
      if (targetUrl.hostname.includes('brave.com') && response.status === 429) {
        res.status(200);
      } else {
        res.status(response.status);
      }

      const contentType = response.headers.get('content-type') || 'text/html';
      res.setHeader('Access-Control-Allow-Origin', '*');

      if (contentType.includes('text/html')) {
        let html = await response.text();
        let blockedTrackersCount = 0;

        // 1. Unwrap DuckDuckGo search result redirect links:
        // //duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com... -> https://example.com
        html = html.replace(
          /(?:https?:)?\/\/duckduckgo\.com\/l\/\?uddg=([^&"'>\s]+)(?:&amp;|&[^"'>\s]*)?/gi,
          (_match, encodedDest) => {
            try {
              return decodeURIComponent(encodedDest);
            } catch {
              return _match;
            }
          }
        );

        // 2. Unwrap Google redirect links (/url?q=...)
        html = html.replace(
          /\/url\?q=([^&"'>\s]+)(?:&amp;|&[^"'>\s]*)?/gi,
          (_match, encodedDest) => {
            try {
              return decodeURIComponent(encodedDest);
            } catch {
              return _match;
            }
          }
        );

        // 3. Active Shield Protection
        let shieldScript = '';
        let shieldStyle = '';
        if (shieldEnabled) {
          TRACKER_PATTERNS.forEach((pattern) => {
            // Match script tags with tracker src
            const scriptMatches = html.match(
              new RegExp(`<script[^>]*src=["'][^"']*${pattern.source}[^"']*["'][^>]*>[\\s\\S]*?<\\/script>`, 'gi')
            );
            if (scriptMatches) {
              blockedTrackersCount += scriptMatches.length;
              html = html.replace(
                new RegExp(`<script[^>]*src=["'][^"']*${pattern.source}[^"']*["'][^>]*>[\\s\\S]*?<\\/script>`, 'gi'),
                '<!-- [Vortex Shield Blocked Tracker Script] -->'
              );
            }

            // Match self-closing or unclosed script tags
            const openScriptMatches = html.match(
              new RegExp(`<script[^>]*src=["'][^"']*${pattern.source}[^"']*["'][^>]*\\/?>`, 'gi')
            );
            if (openScriptMatches) {
              blockedTrackersCount += openScriptMatches.length;
              html = html.replace(
                new RegExp(`<script[^>]*src=["'][^"']*${pattern.source}[^"']*["'][^>]*\\/?>`, 'gi'),
                '<!-- [Vortex Shield Blocked Tracker Tag] -->'
              );
            }
          });

          // Block intrusive ad iframes
          const adIframeMatches = html.match(
            /<iframe[^>]*src=["'][^"']*(?:doubleclick|googlesyndication|adservice|taboola|adnxs|amazon-adsystem)[^"']*["'][^>]*>[\s\S]*?<\/iframe>/gi
          );
          if (adIframeMatches) {
            blockedTrackersCount += adIframeMatches.length;
            html = html.replace(
              /<iframe[^>]*src=["'][^"']*(?:doubleclick|googlesyndication|adservice|taboola|adnxs|amazon-adsystem)[^"']*["'][^>]*>[\s\S]*?<\/iframe>/gi,
              '<!-- [Vortex Shield Blocked Ad Frame] -->'
            );
          }

          // CSS to hide common ad units
          shieldStyle = `
            <style id="vortex-shield-css">
              .adsbygoogle, .ad-banner, .advertisement, [id*="ad-container"],
              [class*="ad-banner"], [class*="ad-box"], [id*="google_ads"],
              iframe[src*="doubleclick"], iframe[src*="adservice"],
              .ad-slot, .ad_unit, #header-ad, #footer-ad {
                display: none !important;
                visibility: hidden !important;
                height: 0 !important;
                pointer-events: none !important;
              }
            </style>
          `;

          // Active sandbox script to block unauthorized popup windows, tracking beacons, and alerts
          shieldScript = `
            <script id="vortex-shield-enforcer">
              window.open = function(url) {
                console.log('[Vortex Shield] Blocked unauthorized window popup:', url);
                if (url && typeof url === 'string') {
                  try {
                    window.parent.postMessage({ type: 'VORTEX_NAVIGATE', url: url }, '*');
                  } catch(e) {}
                }
                return null;
              };
              window.alert = function(msg) { console.log('[Vortex Shield Alert Blocked]', msg); };
              window.confirm = function() { return false; };
              // Dummy mocks to prevent crashes when trackers are blocked
              window.ga = window.gtag = window.fbq = window._fbq = function() {};
            </script>
          `;
        }

        const baseTag = `<base href="${response.url || targetUrl.href}">`;

        // Navigation interceptor & bridge script:
        // Intercepts all link clicks, form submits, and dynamic requests so they stay inside the Vortex browser!
        const bridgeScript = `
          <script id="vortex-frame-bridge">
            window.__VORTEX_PAGE_METADATA__ = {
              title: document.title,
              url: ${JSON.stringify(response.url || targetUrl.href)},
              blockedCount: ${blockedTrackersCount},
              shield: ${shieldEnabled},
              engine: 'ultraviolet'
            };

            // Proxy dynamic API requests (DuckDuckGo, Brave, Google) through Vortex proxy to prevent CORS blocks
            (function() {
              var origFetch = window.fetch;
              if (origFetch) {
                window.fetch = function(input, init) {
                  try {
                    var urlStr = typeof input === 'string' ? input : (input && input.url ? input.url : String(input));
                    var baseOrigin = ${JSON.stringify(targetUrl.origin)};
                    var targetBase = ${JSON.stringify(targetUrl.href)};
                    var resolved = urlStr;
                    if (urlStr.startsWith('//')) {
                      resolved = 'https:' + urlStr;
                    } else if (urlStr.startsWith('/')) {
                      resolved = baseOrigin + urlStr;
                    } else if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
                      resolved = new URL(urlStr, targetBase).href;
                    }
                    if ((resolved.startsWith('http://') || resolved.startsWith('https://')) &&
                        !resolved.includes('/api/proxy') && !resolved.includes('/service/')) {
                      var proxyUrl = '/api/proxy?url=' + encodeURIComponent(resolved) + '&shield=${shieldEnabled}';
                      return origFetch.call(this, proxyUrl, init);
                    }
                  } catch(e) {}
                  return origFetch.apply(this, arguments);
                };
              }

              var origOpen = window.XMLHttpRequest && window.XMLHttpRequest.prototype.open;
              if (origOpen) {
                window.XMLHttpRequest.prototype.open = function(method, url) {
                  try {
                    var urlStr = String(url);
                    var baseOrigin = ${JSON.stringify(targetUrl.origin)};
                    var targetBase = ${JSON.stringify(targetUrl.href)};
                    var resolved = urlStr;
                    if (urlStr.startsWith('//')) {
                      resolved = 'https:' + urlStr;
                    } else if (urlStr.startsWith('/')) {
                      resolved = baseOrigin + urlStr;
                    } else if (!urlStr.startsWith('http://') && !urlStr.startsWith('https://')) {
                      resolved = new URL(urlStr, targetBase).href;
                    }
                    if ((resolved.startsWith('http://') || resolved.startsWith('https://')) &&
                        !resolved.includes('/api/proxy') && !resolved.includes('/service/')) {
                      url = '/api/proxy?url=' + encodeURIComponent(resolved) + '&shield=${shieldEnabled}';
                    }
                  } catch(e) {}
                  return origOpen.apply(this, arguments);
                };
              }
            })();

            // Notify parent window of loaded page metadata
            try {
              window.parent.postMessage({
                type: 'VORTEX_FRAME_LOADED',
                title: document.title || ${JSON.stringify(targetUrl.hostname)},
                url: ${JSON.stringify(response.url || targetUrl.href)},
                blockedCount: ${blockedTrackersCount}
              }, '*');
            } catch(e) {}

            // Intercept link clicks to navigate smoothly inside Vortex
            document.addEventListener('click', function(e) {
              var target = e.target;
              while (target && target.tagName !== 'A') {
                target = target.parentElement;
              }
              if (target && target.href && !target.href.startsWith('javascript:')) {
                var href = target.href;
                // Unwrap DuckDuckGo redirect
                if (href.indexOf('uddg=') !== -1) {
                  try {
                    var match = href.match(/uddg=([^&]+)/);
                    if (match && match[1]) {
                      href = decodeURIComponent(match[1]);
                    }
                  } catch(err) {}
                }
                // Unwrap Google redirect (/url?q=...)
                if (href.indexOf('/url?q=') !== -1) {
                  try {
                    var gMatch = href.match(/\/url\?q=([^&]+)/);
                    if (gMatch && gMatch[1]) {
                      href = decodeURIComponent(gMatch[1]);
                    }
                  } catch(err) {}
                }
                e.preventDefault();
                try {
                  window.parent.postMessage({
                    type: 'VORTEX_NAVIGATE',
                    url: href
                  }, '*');
                } catch(err) {
                  window.location.href = href;
                }
              }
            }, true);

            // Intercept form submissions (e.g. search boxes in DuckDuckGo, Brave, Google, Bing)
            document.addEventListener('submit', function(e) {
              var form = e.target;
              if (form && form.action) {
                var method = (form.method || 'GET').toUpperCase();
                if (method === 'GET') {
                  e.preventDefault();
                  var formData = new FormData(form);
                  var params = new URLSearchParams(formData);
                  var actionUrl = form.action;
                  var targetFullUrl = actionUrl + (actionUrl.indexOf('?') !== -1 ? '&' : '?') + params.toString();
                  try {
                    window.parent.postMessage({
                      type: 'VORTEX_NAVIGATE',
                      url: targetFullUrl
                    }, '*');
                  } catch(err) {
                    window.location.href = targetFullUrl;
                  }
                }
              }
            }, true);
          </script>
        `;

        const injected = `${baseTag}${shieldStyle}${shieldScript}${bridgeScript}`;

        if (html.includes('<head>')) {
          html = html.replace('<head>', `<head>${injected}`);
        } else if (html.includes('<head ')) {
          html = html.replace(/<head[^>]*>/, `$&${injected}`);
        } else {
          html = `${injected}${html}`;
        }

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Vortex-Blocked-Trackers', blockedTrackersCount.toString());
        res.setHeader('X-Proxy-Engine', 'Ultraviolet-Vortex');
        return res.send(html);
      } else {
        res.setHeader('Content-Type', contentType);
        const arrayBuffer = await response.arrayBuffer();
        return res.send(Buffer.from(arrayBuffer));
      }
    } catch (err: any) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(502).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Navigation Notice - Vortex</title>
          <style>
            body { background: #070512; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .card { background: #130d2e; border: 2px solid #8b5cf6; border-radius: 16px; padding: 32px; max-width: 520px; box-shadow: 0 10px 30px rgba(139,92,246,0.3); text-align: center; }
            h1 { color: #d8b4fe; font-size: 20px; margin-bottom: 12px; font-weight: 700; }
            p { color: #94a3b8; font-size: 13px; line-height: 1.6; margin-bottom: 20px; }
            .url { background: rgba(0,0,0,0.5); padding: 8px 12px; border-radius: 8px; font-family: monospace; color: #c084fc; word-break: break-all; margin-bottom: 20px; font-size: 12px; }
            .btn { background: #8b5cf6; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; margin: 0 4px; font-size: 13px; }
            .btn:hover { background: #7c3aed; }
            .btn-outline { background: transparent; border: 1px solid #8b5cf6; color: #d8b4fe; }
          </style>
        </head>
        <body>
          <div class="card">
            <h1>Cannot Reach Destination</h1>
            <div class="url">${targetUrl.href}</div>
            <p>Vortex could not connect to this server or the request timed out.</p>
            <p style="font-size: 11px; color: #64748b;">${err.message || 'Connection error'}</p>
            <a href="javascript:location.reload()" class="btn">Try Again</a>
            <a href="${targetUrl.href}" target="_blank" class="btn btn-outline">Open Direct</a>
          </div>
        </body>
        </html>
      `);
    }
  };

  // Ultraviolet standard route: /service/:encodedUrl (supports GET and POST)
  app.all('/service/:encodedUrl(*)', (req, res) => {
    const rawParam = req.params.encodedUrl;
    const shieldEnabled = req.query.shield === 'true';
    let targetUrl = '';
    try {
      targetUrl = xor.decode(rawParam);
    } catch {
      targetUrl = rawParam;
    }
    return handleProxyRequest(targetUrl, shieldEnabled, req, res);
  });

  // Compatibility /api/proxy endpoint (supports GET and POST)
  app.all('/api/proxy', (req, res) => {
    const rawUrl = (req.query.url as string) || (req.body?.url as string);
    const shieldEnabled = req.query.shield === 'true';
    if (!rawUrl) return res.status(400).send('Missing url');
    return handleProxyRequest(rawUrl, shieldEnabled, req, res);
  });

  // Serve static files or Vite dev server
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist/index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Vortex Ultraviolet Browser running at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start Vortex server:', err);
  process.exit(1);
});
