/**
 * GET /api/proxy?url=<encoded-url>
 * 服务端中转 HTTP 请求，绕过浏览器的 CORS 限制。
 * 用于抓取第三方 Clash 订阅链接。
 */
module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    return res.end('Method not allowed');
  }

  var url = require('url');
  var target = url.parse(req.url, true).query.url;

  if (!target) {
    res.statusCode = 400;
    return res.end('Missing "url" parameter');
  }

  try {
    var resp = await fetch(target, {
      headers: {
        'User-Agent': 'ClashMetaConfigGenerator/1.0',
        'Accept': 'text/plain, application/x-yaml, */*'
      }
    });

    if (!resp.ok) {
      res.statusCode = 502;
      return res.end('Upstream error: HTTP ' + resp.status);
    }

    var body = await resp.text();

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=120');
    res.end(body);
  } catch (e) {
    res.statusCode = 502;
    res.end('Proxy error: ' + e.message);
  }
};
