/**
 * GET /api/sub?urls=<base64-json>
 *
 * urls 是 base64 编码的 JSON 数组: [{"name":"订阅1","url":"https://..."}]
 *
 * 动态抓取所有订阅链接 → 解析节点 → 国家检测重命名 → 生成多出口监听器配置 → 返回 YAML
 */
const jsyaml = require('js-yaml');

// ======================== 协议解析 ========================

function parseVmess(uri) {
  try {
    var b64 = uri.replace('vmess://', '');
    var json = JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));
    var p = { name: json.ps || 'VMess 节点', type: 'vmess', server: json.add, port: parseInt(json.port) || 443, uuid: json.id, alterId: parseInt(json.aid) || 0, cipher: json.scy || 'auto', udp: true };
    if (json.net) p.network = json.net;
    if (json.net === 'ws') { p['ws-opts'] = { path: json.path || '/', headers: {} }; if (json.host) p['ws-opts'].headers.Host = json.host; }
    else if (json.net === 'grpc') p['grpc-opts'] = { 'grpc-service-name': json.path || '' };
    else if (json.net === 'h2') p['h2-opts'] = { host: [json.host] || [], path: json.path || '' };
    if (json.tls === 'tls') {
      p.tls = true;
      if (json.sni) p.servername = json.sni;
      if (json.alpn) p.alpn = json.alpn.split(',').map(function(s) { return s.trim(); });
      if (json.fp) p['client-fingerprint'] = json.fp;
    }
    return p;
  } catch (e) { return null; }
}

function parseVless(uri) {
  try {
    var url = new URL(uri);
    var p = { name: decodeURIComponent((url.hash || '').slice(1) || 'VLESS 节点'), type: 'vless', server: url.hostname, port: parseInt(url.port) || 443, uuid: url.username, udp: true };
    var params = url.searchParams;
    p.cipher = params.get('encryption') || 'none';
    p.network = params.get('type') || 'tcp';
    if (p.network === 'ws') { p['ws-opts'] = { path: params.get('path') || '/', headers: {} }; if (params.get('host')) p['ws-opts'].headers.Host = params.get('host'); }
    else if (p.network === 'grpc') p['grpc-opts'] = { 'grpc-service-name': params.get('serviceName') || '' };
    var sec = params.get('security') || 'none';
    if (sec === 'reality') {
      p.tls = true;
      p['reality-opts'] = { 'public-key': params.get('pbk') || '', 'short-id': params.get('sid') || '' };
      if (params.get('spx')) p['reality-opts']['spider-x'] = params.get('spx');
      if (params.get('sni')) p.servername = params.get('sni');
      if (params.get('fp')) p['client-fingerprint'] = params.get('fp');
      if (params.get('flow')) p.flow = params.get('flow');
    } else if (sec === 'tls') {
      p.tls = true;
      if (params.get('sni')) p.servername = params.get('sni');
      if (params.get('fp')) p['client-fingerprint'] = params.get('fp');
      if (params.get('alpn')) p.alpn = params.get('alpn').split(',').map(function(s) { return s.trim(); });
      if (params.get('flow')) p.flow = params.get('flow');
    }
    return p;
  } catch (e) { return null; }
}

function parseTrojan(uri) {
  try {
    var url = new URL(uri);
    var p = { name: decodeURIComponent((url.hash || '').slice(1) || 'Trojan 节点'), type: 'trojan', server: url.hostname, port: parseInt(url.port) || 443, password: url.username, udp: true };
    var params = url.searchParams;
    p.network = params.get('type') || 'tcp';
    if (p.network === 'ws') { p['ws-opts'] = { path: params.get('path') || '/', headers: {} }; if (params.get('host')) p['ws-opts'].headers.Host = params.get('host'); }
    else if (p.network === 'grpc') p['grpc-opts'] = { 'grpc-service-name': params.get('serviceName') || '' };
    if ((params.get('security') || 'tls') === 'tls') {
      p.tls = true;
      if (params.get('sni')) p.servername = params.get('sni');
      if (params.get('fp')) p['client-fingerprint'] = params.get('fp');
      if (params.get('alpn')) p.alpn = params.get('alpn').split(',').map(function(s) { return s.trim(); });
    }
    return p;
  } catch (e) { return null; }
}

function parseSS(uri) {
  try {
    var withoutHash = uri.split('#')[0];
    var name = uri.includes('#') ? decodeURIComponent(uri.split('#')[1]) : 'SS 节点';
    var rest = withoutHash.replace('ss://', '');
    var method, password, server, port;
    if (rest.includes('@')) {
      var parts = rest.split('@'), d = Buffer.from(parts[0], 'base64').toString('utf-8'), ci = d.indexOf(':');
      method = d.slice(0, ci); password = d.slice(ci + 1);
      var lc = parts[1].lastIndexOf(':');
      server = parts[1].slice(0, lc);
      if (server.startsWith('[') && server.endsWith(']')) server = server.slice(1, -1);
      port = parseInt(parts[1].slice(lc + 1)) || 8388;
    } else {
      var d = Buffer.from(rest, 'base64').toString('utf-8'), credAddr = d.split('@'), ci = credAddr[0].indexOf(':');
      method = credAddr[0].slice(0, ci); password = credAddr[0].slice(ci + 1);
      var lc = credAddr[1].lastIndexOf(':');
      server = credAddr[1].slice(0, lc);
      if (server.startsWith('[') && server.endsWith(']')) server = server.slice(1, -1);
      port = parseInt(credAddr[1].slice(lc + 1)) || 8388;
    }
    return { name: name, type: 'ss', server: server, port: port, cipher: method, password: password, udp: true };
  } catch (e) { return null; }
}

function parseHysteria2(uri) {
  try {
    var url = new URL(uri), params = url.searchParams;
    var p = { name: decodeURIComponent((url.hash || '').slice(1) || 'Hysteria2 节点'), type: 'hysteria2', server: url.hostname, port: parseInt(url.port) || 443, password: url.username || params.get('auth') || '', udp: true };
    if (params.get('sni')) p.sni = params.get('sni');
    if (params.get('insecure') === '1' || params.get('insecure') === 'true') p['skip-cert-verify'] = true;
    if (params.get('mport')) p.ports = params.get('mport');
    if (params.get('obfs')) { p.obfs = { type: params.get('obfs') }; if (params.get('obfs-password')) p.obfs.password = params.get('obfs-password'); }
    if (params.get('alpn')) p.alpn = params.get('alpn').split(',').map(function(s) { return s.trim(); });
    return p;
  } catch (e) { return null; }
}

function parseTuic(uri) {
  try {
    var url = new URL(uri), params = url.searchParams;
    var p = { name: decodeURIComponent((url.hash || '').slice(1) || 'TUIC 节点'), type: 'tuic', server: url.hostname, port: parseInt(url.port) || 443, uuid: url.username, password: url.password || '', udp: true };
    if (params.get('congestion_control')) p['congestion-controller'] = params.get('congestion_control');
    if (params.get('alpn')) p.alpn = params.get('alpn').split(',').map(function(s) { return s.trim(); });
    if (params.get('sni')) p.sni = params.get('sni');
    if (params.get('allow_insecure') === '1' || params.get('allow_insecure') === 'true') p['skip-cert-verify'] = true;
    if (params.get('disable_sni') === '1' || params.get('disable_sni') === 'true') p['disable-sni'] = true;
    if (params.get('reduce_rtt') === '1' || params.get('reduce_rtt') === 'true') p['reduce-rtt'] = true;
    if (params.get('udp_relay_mode')) p['udp-relay-mode'] = params.get('udp_relay_mode');
    return p;
  } catch (e) { return null; }
}

function parseLink(link) {
  var t = link.trim();
  if (!t) return null;
  if (t.startsWith('vmess://')) return parseVmess(t);
  if (t.startsWith('vless://')) return parseVless(t);
  if (t.startsWith('trojan://')) return parseTrojan(t);
  if (t.startsWith('ss://')) return parseSS(t);
  if (t.startsWith('hysteria2://') || t.startsWith('hy2://')) return parseHysteria2(t);
  if (t.startsWith('tuic://')) return parseTuic(t);
  return null;
}

// ======================== 从文本提取代理 ========================

function extractProxies(txt) {
  var result = [];
  // 尝试 YAML 格式
  try {
    var cfg = jsyaml.load(txt);
    if (cfg && cfg.proxies && Array.isArray(cfg.proxies)) return cfg.proxies;
  } catch (_) {}
  // 逐行解析链接
  var lines = txt.split('\n').filter(function(l) { return l.trim(); });
  for (var i = 0; i < lines.length; i++) {
    var p = parseLink(lines[i]);
    if (p) result.push(p);
  }
  return result;
}

// ======================== 国家检测 ========================

var COUNTRY_MAP = {
  'Japan': '日本','South Korea': '韩国','Singapore': '新加坡','United States': '美国','Hong Kong': '香港','Taiwan': '台湾','China': '中国','Germany': '德国','Netherlands': '荷兰','United Kingdom': '英国','France': '法国','Canada': '加拿大','Australia': '澳大利亚','Russia': '俄罗斯','India': '印度','Brazil': '巴西','Thailand': '泰国','Vietnam': '越南','Malaysia': '马来西亚','Indonesia': '印度尼西亚','Philippines': '菲律宾','Sweden': '瑞典','Switzerland': '瑞士','Italy': '意大利','Spain': '西班牙','Turkey': '土耳其','United Arab Emirates': '阿联酋','South Africa': '南非','Macau': '澳门','Finland': '芬兰','Poland': '波兰','Luxembourg': '卢森堡','Belgium': '比利时','Austria': '奥地利','Norway': '挪威','Denmark': '丹麦','Ireland': '爱尔兰','Portugal': '葡萄牙','Czech Republic': '捷克','Romania': '罗马尼亚','Argentina': '阿根廷','Chile': '智利','Mexico': '墨西哥','Colombia': '哥伦比亚','New Zealand': '新西兰',
};

var FLAG_TO_COUNTRY = {
  '🇭🇰': '香港','🇺🇸': '美国','🇯🇵': '日本','🇳🇱': '荷兰','🇷🇺': '俄罗斯','🇩🇪': '德国','🇨🇭': '瑞士','🇫🇷': '法国','🇬🇧': '英国','🇸🇪': '瑞典','🇧🇬': '保加利亚','🇦🇹': '奥地利','🇮🇪': '爱尔兰','🇹🇷': '土耳其','🇭🇺': '匈牙利','🇰🇷': '韩国','🇨🇳': '中国','🇨🇦': '加拿大','🇦🇺': '澳大利亚','🇦🇪': '阿联酋','🇮🇳': '印度','🇮🇩': '印尼','🇧🇷': '巴西','🇦🇷': '阿根廷','🇨🇱': '智利','🇸🇬': '新加坡','🇲🇾': '马来西亚','🇹🇭': '泰国','🇻🇳': '越南','🇵🇭': '菲律宾','🇮🇹': '意大利','🇪🇸': '西班牙','🇳🇴': '挪威','🇩🇰': '丹麦','🇫🇮': '芬兰','🇧🇪': '比利时','🇵🇱': '波兰','🇨🇿': '捷克','🇷🇴': '罗马尼亚','🇿🇦': '南非','🇲🇴': '澳门',
};

var KEYWORD_TO_COUNTRY = {
  'hong kong': '香港','usa': '美国','japan': '日本','netherlands': '荷兰','russia': '俄罗斯','germany': '德国','switzerland': '瑞士','france': '法国','united kingdom': '英国','sweden': '瑞典','bulgaria': '保加利亚','austria': '奥地利','ireland': '爱尔兰','turkey': '土耳其','hungary': '匈牙利','korea': '韩国','taiwan': '台湾','canada': '加拿大','australia': '澳大利亚','united arab emirates': '阿联酋','india': '印度','indonesia': '印尼','brazil': '巴西','argentina': '阿根廷','chile': '智利','singapore': '新加坡','malaysia': '马来西亚','thailand': '泰国','vietnam': '越南','philippines': '菲律宾','italy': '意大利','spain': '西班牙','norway': '挪威','denmark': '丹麦','finland': '芬兰','belgium': '比利时','poland': '波兰','seattle': '美国','los angeles': '美国','san jose': '美国','sydney': '澳大利亚','moscow': '俄罗斯','st. petersburg': '俄罗斯','london': '英国','amsterdam': '荷兰','frankfurt': '德国',
};

function extractCountryFromName(name) {
  for (var flag in FLAG_TO_COUNTRY) { if (name.indexOf(flag) !== -1) return FLAG_TO_COUNTRY[flag]; }
  var lower = name.toLowerCase();
  for (var kw in KEYWORD_TO_COUNTRY) { if (lower.indexOf(kw) !== -1) return KEYWORD_TO_COUNTRY[kw]; }
  return null;
}

var geoCache = {};

async function lookupCountry(server) {
  if (geoCache[server]) return geoCache[server];
  try {
    // 服务端可以直接用 HTTP，没有浏览器混合内容限制
    var resp = await fetch('http://ip-api.com/json/' + encodeURIComponent(server) + '?fields=country');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    var cn = COUNTRY_MAP[data.country] || data.country || '未知';
    geoCache[server] = cn;
    return cn;
  } catch (e) {
    geoCache[server] = '未知';
    return '未知';
  }
}

async function detectCountries(proxies) {
  var needLookup = [];
  for (var i = 0; i < proxies.length; i++) {
    var cn = extractCountryFromName(proxies[i].name);
    if (cn) { proxies[i]._country = cn; }
    else { needLookup.push(proxies[i]); }
  }
  if (needLookup.length === 0) return;
  // 去重 server 后并行查询
  var servers = [], seen = {};
  for (var i = 0; i < needLookup.length; i++) {
    var s = needLookup[i].server;
    if (!seen[s]) { seen[s] = true; servers.push(s); }
  }
  // 逐个查询（ip-api 免费版限制 45/min，加延迟）
  for (var i = 0; i < servers.length; i++) {
    await lookupCountry(servers[i]);
    if (i < servers.length - 1) await new Promise(function(r) { setTimeout(r, 200); });
  }
  for (var i = 0; i < needLookup.length; i++) {
    needLookup[i]._country = geoCache[needLookup[i].server] || '未知';
  }
}

// ======================== 抓取订阅 ========================

async function fetchOneSub(url) {
  var resp = await fetch(url);
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  var rawText = await resp.text();
  if (!rawText || rawText.trim().length === 0) throw new Error('返回空内容');

  var proxies = extractProxies(rawText);
  if (proxies.length === 0) {
    try {
      var decoded = Buffer.from(rawText.trim(), 'base64').toString('utf-8');
      if (decoded) proxies = extractProxies(decoded);
    } catch (_) {}
  }
  return proxies;
}

// ======================== 主处理函数 ========================

async function generateConfig(subs) {
  // Step 1: 并行抓取
  var allProxies = [];
  for (var i = 0; i < subs.length; i++) {
    var sub = subs[i];
    try {
      var proxies = await fetchOneSub(sub.url);
      for (var j = 0; j < proxies.length; j++) {
        proxies[j]._source = sub.name;
        proxies[j]._origName = proxies[j].name;
      }
      allProxies = allProxies.concat(proxies);
    } catch (e) {
      console.error('抓取失败:', sub.name, e.message);
    }
  }

  if (allProxies.length === 0) throw new Error('所有订阅均未抓取到节点');

  // Step 2: 去重
  var seen = {}, unique = [];
  for (var i = 0; i < allProxies.length; i++) {
    var key = allProxies[i].server + ':' + allProxies[i].port;
    if (!seen[key]) { seen[key] = true; unique.push(allProxies[i]); }
  }
  allProxies = unique;

  // Step 3: 国家检测并重命名
  await detectCountries(allProxies);
  for (var i = 0; i < allProxies.length; i++) {
    var p = allProxies[i];
    p.name = p._source + '-' + (p._country || '未知') + '-' + (p._origName || p.name);
  }

  // Step 4: 生成配置
  var lType = 'mixed', startPort = 8000, lAddr = '127.0.0.1';
  var finalProxies = allProxies.map(function(p, i) {
    var clean = {};
    for (var k in p) {
      if (k !== '_source' && k !== '_origName' && k !== '_country') clean[k] = p[k];
    }
    var parts = clean.name.split('-');
    if (parts.length >= 2) {
      clean.name = parts[0] + '-' + parts[1] + '-' + (startPort + i) + '-' + parts.slice(2).join('-');
    }
    return clean;
  });

  var listeners = finalProxies.map(function(p, i) {
    return { name: p.type + '-' + p.name, type: lType, address: lAddr, port: startPort + i, proxy: p.name };
  });

  var proxyNames = finalProxies.map(function(p) { return p.name; });

  var config = {
    proxies: finalProxies,
    listeners: listeners,
    'proxy-groups': [{ name: 'Proxy', type: 'select', proxies: proxyNames }],
    rules: ['MATCH,Proxy'],
    dns: { enable: true, ipv6: false },
  };

  return jsyaml.dump(config, { lineWidth: -1, quotingType: '"' });
}

// ======================== Vercel Handler ========================

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'text/plain');
    return res.end('Method not allowed');
  }

  var url = require('url');
  var query = url.parse(req.url, true).query;
  var urlsParam = query.urls;

  // 兼容旧格式: ?data=<base64-yaml>
  if (!urlsParam && query.data) {
    try {
      var yaml = Buffer.from(query.data, 'base64').toString('utf-8');
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.setHeader('Access-Control-Allow-Origin', '*');
      return res.end(yaml);
    } catch (e) {
      res.statusCode = 400;
      res.setHeader('Content-Type', 'text/plain');
      return res.end('Invalid base64 data');
    }
  }

  if (!urlsParam) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/plain');
    return res.end('Missing "urls" parameter');
  }

  var subs;
  try {
    subs = JSON.parse(Buffer.from(urlsParam, 'base64').toString('utf-8'));
    if (!Array.isArray(subs) || subs.length === 0) throw new Error('invalid format');
  } catch (e) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/plain');
    return res.end('Invalid urls parameter: must be base64-encoded JSON array of {name, url}');
  }

  try {
    var yaml = await generateConfig(subs);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.end(yaml);
  } catch (e) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain');
    res.end('Generate error: ' + e.message);
  }
};
