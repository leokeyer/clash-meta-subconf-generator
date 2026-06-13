/**
 * GET /api/sub?data=<base64-yaml>
 * 解码 base64 后返回纯文本 YAML，供 Clash 客户端订阅
 */
module.exports = function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'text/plain');
    return res.end('Method not allowed');
  }

  // 解析 query string
  var url = require('url');
  var data = url.parse(req.url, true).query.data;

  if (!data) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/plain');
    return res.end('Missing "data" parameter');
  }

  try {
    // base64 解码
    var yaml = Buffer.from(data, 'base64').toString('utf-8');

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.end(yaml);
  } catch (e) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Invalid base64 data: ' + e.message);
  }
};
