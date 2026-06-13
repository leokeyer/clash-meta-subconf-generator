/**
 * GET /api/proxy?url=<encoded-url>
 * 服务端中转 HTTP 请求，绕过浏览器的 CORS 限制。
 * 仅允许公网 HTTPS URL，阻止 SSRF 攻击。
 */
var url = require('url');
var dns = require('dns');

// 内网 IP 段（IPv4）
var PRIVATE_RANGES = [
  ['10.0.0.0',     '10.255.255.255'],
  ['172.16.0.0',   '172.31.255.255'],
  ['192.168.0.0',  '192.168.255.255'],
  ['127.0.0.0',    '127.255.255.255'],
  ['169.254.0.0',  '169.254.255.255'],
  ['0.0.0.0',      '0.255.255.255'],
];

function ipToInt(ip) {
  var parts = ip.split('.');
  // 使用乘法避免位运算符号溢出
  return ((+parts[0] * 256 + +parts[1]) * 256 + +parts[2]) * 256 + +parts[3];
}

function isPrivateIp(ip) {
  var num = ipToInt(ip);
  for (var i = 0; i < PRIVATE_RANGES.length; i++) {
    if (num >= ipToInt(PRIVATE_RANGES[i][0]) && num <= ipToInt(PRIVATE_RANGES[i][1])) {
      return true;
    }
  }
  return false;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    return res.end('Method not allowed');
  }

  var target = url.parse(req.url, true).query.url;

  if (!target) {
    res.statusCode = 400;
    return res.end('Missing "url" parameter');
  }

  // 1. 校验协议：仅允许 http/https
  var parsed = url.parse(target);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    res.statusCode = 403;
    return res.end('Only HTTP/HTTPS URLs are allowed');
  }

  // 2. DNS 解析 + 内网 IP 拦截（防止 SSRF）
  try {
    var addresses = await dns.promises.resolve4(parsed.hostname);
    if (addresses.length === 0) {
      res.statusCode = 502;
      return res.end('Cannot resolve hostname');
    }
    for (var i = 0; i < addresses.length; i++) {
      if (isPrivateIp(addresses[i])) {
        res.statusCode = 403;
        return res.end('Access to internal/private IP addresses is blocked');
      }
    }
  } catch (e) {
    res.statusCode = 502;
    return res.end('DNS resolution failed: ' + e.message);
  }

  // 3. 发起请求（带超时和大小限制）
  try {
    var controller = new AbortController();
    var timeout = setTimeout(function() { controller.abort(); }, 15000);

    var resp = await fetch(target, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'ClashMetaConfigGenerator/1.0',
        'Accept': 'text/plain, application/x-yaml, */*'
      }
    });
    clearTimeout(timeout);

    if (!resp.ok) {
      res.statusCode = 502;
      return res.end('Upstream error: HTTP ' + resp.status);
    }

    // 限制响应体大小：最大 2MB
    var body = await resp.text();
    if (body.length > 2 * 1024 * 1024) {
      res.statusCode = 413;
      return res.end('Response too large');
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=120');
    res.end(body);
  } catch (e) {
    res.statusCode = 502;
    if (e.name === 'AbortError') {
      return res.end('Request timeout');
    }
    res.end('Proxy error: ' + e.message);
  }
};
