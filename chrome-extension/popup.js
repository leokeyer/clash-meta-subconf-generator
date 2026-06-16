// ======================== 全局状态 ========================
let parsedProxies = [];      // 已解析的代理节点列表
let baseConfig = null;       // 从 YAML 文本解析出的基础配置对象

// 英文国名 → 中文（覆盖常见 VPS 地区）
const COUNTRY_MAP = {
  'Japan': '日本', 'South Korea': '韩国', 'Singapore': '新加坡',
  'United States': '美国', 'Hong Kong': '香港', 'Taiwan': '台湾',
  'China': '中国', 'Germany': '德国', 'Netherlands': '荷兰',
  'United Kingdom': '英国', 'France': '法国', 'Canada': '加拿大',
  'Australia': '澳大利亚', 'Russia': '俄罗斯', 'India': '印度',
  'Brazil': '巴西', 'Thailand': '泰国', 'Vietnam': '越南',
  'Malaysia': '马来西亚', 'Indonesia': '印度尼西亚',
  'Philippines': '菲律宾', 'Sweden': '瑞典', 'Switzerland': '瑞士',
  'Italy': '意大利', 'Spain': '西班牙', 'Turkey': '土耳其',
  'United Arab Emirates': '阿联酋', 'South Africa': '南非',
  'Macau': '澳门', 'Finland': '芬兰', 'Poland': '波兰',
  'Luxembourg': '卢森堡', 'Belgium': '比利时', 'Austria': '奥地利',
  'Norway': '挪威', 'Denmark': '丹麦', 'Ireland': '爱尔兰',
  'Portugal': '葡萄牙', 'Czech Republic': '捷克', 'Romania': '罗马尼亚',
  'Argentina': '阿根廷', 'Chile': '智利', 'Mexico': '墨西哥',
  'Colombia': '哥伦比亚', 'New Zealand': '新西兰',
};

// ======================== 协议解析 ========================

/**
 * 解析 VMess 链接
 * 格式: vmess://base64(json)
 */
function parseVmess(uri) {
  try {
    const b64 = uri.replace('vmess://', '');
    const json = JSON.parse(atob(b64));
    const proxy = {
      name: json.ps || 'VMess 节点',
      type: 'vmess',
      server: json.add,
      port: parseInt(json.port) || 443,
      uuid: json.id,
      alterId: parseInt(json.aid) || 0,
      cipher: json.scy || 'auto',
      udp: true,
    };
    if (json.net) proxy.network = json.net;
    if (json.net === 'ws') {
      proxy.ws_opts = { path: json.path || '/', headers: {} };
      if (json.host) proxy.ws_opts.headers.Host = json.host;
    } else if (json.net === 'grpc') {
      proxy.grpc_opts = { grpc_service_name: json.path || '' };
    } else if (json.net === 'h2') {
      proxy.h2_opts = { host: [json.host] || [], path: json.path || '' };
    }
    if (json.tls === 'tls') {
      proxy.tls = true;
      if (json.sni) proxy.servername = json.sni;
      if (json.alpn) proxy.alpn = json.alpn.split(',').map(s => s.trim());
      if (json.fp) proxy.client_fingerprint = json.fp;
    }
    return proxy;
  } catch (e) {
    console.error('VMess 解析失败:', e);
    return null;
  }
}

/**
 * 解析 VLESS 链接
 * 格式: vless://uuid@server:port?params#name
 */
function parseVless(uri) {
  try {
    const url = new URL(uri);
    const proxy = {
      name: decodeURIComponent(url.hash?.slice(1) || 'VLESS 节点'),
      type: 'vless',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      uuid: url.username,
      udp: true,
    };
    const params = url.searchParams;
    proxy.cipher = params.get('encryption') || 'none';
    const type = params.get('type') || 'tcp';
    proxy.network = type;
    if (type === 'ws') {
      proxy.ws_opts = { path: params.get('path') || '/', headers: {} };
      if (params.get('host')) proxy.ws_opts.headers.Host = params.get('host');
    } else if (type === 'grpc') {
      proxy.grpc_opts = { grpc_service_name: params.get('serviceName') || '' };
    }
    const security = params.get('security') || 'none';
    if (security === 'reality') {
      proxy.tls = true;
      proxy.reality_opts = {
        public_key: params.get('pbk') || '',
        short_id: params.get('sid') || '',
      };
      if (params.get('sni')) proxy.servername = params.get('sni');
      if (params.get('fp')) proxy.client_fingerprint = params.get('fp');
      if (params.get('flow')) proxy.flow = params.get('flow');
    } else if (security === 'tls') {
      proxy.tls = true;
      if (params.get('sni')) proxy.servername = params.get('sni');
      if (params.get('fp')) proxy.client_fingerprint = params.get('fp');
      if (params.get('alpn')) proxy.alpn = params.get('alpn').split(',').map(s => s.trim());
      if (params.get('flow')) proxy.flow = params.get('flow');
    }
    return proxy;
  } catch (e) {
    console.error('VLESS 解析失败:', e);
    return null;
  }
}

/**
 * 解析 Trojan 链接
 * 格式: trojan://password@server:port?params#name
 */
function parseTrojan(uri) {
  try {
    const url = new URL(uri);
    const proxy = {
      name: decodeURIComponent(url.hash?.slice(1) || 'Trojan 节点'),
      type: 'trojan',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password: url.username,
      udp: true,
    };
    const params = url.searchParams;
    const type = params.get('type') || 'tcp';
    proxy.network = type;
    if (type === 'ws') {
      proxy.ws_opts = { path: params.get('path') || '/', headers: {} };
      if (params.get('host')) proxy.ws_opts.headers.Host = params.get('host');
    } else if (type === 'grpc') {
      proxy.grpc_opts = { grpc_service_name: params.get('serviceName') || '' };
    }
    const security = params.get('security') || 'tls';
    if (security === 'tls') {
      proxy.tls = true;
      if (params.get('sni')) proxy.servername = params.get('sni');
      if (params.get('fp')) proxy.client_fingerprint = params.get('fp');
      if (params.get('alpn')) proxy.alpn = params.get('alpn').split(',').map(s => s.trim());
    }
    return proxy;
  } catch (e) {
    console.error('Trojan 解析失败:', e);
    return null;
  }
}

/**
 * 解析 Shadowsocks (SS) 链接
 * 格式: ss://base64(method:password@server:port)#name
 * 或:   ss://base64(method:password)@server:port#name (SIP002)
 */
function parseSS(uri) {
  try {
    const withoutHash = uri.split('#')[0];
    const hashPart = uri.includes('#') ? uri.split('#')[1] : '';
    const name = hashPart ? decodeURIComponent(hashPart) : 'SS 节点';

    let rest = withoutHash.replace('ss://', '');
    let method, password, server, port;

    if (rest.includes('@')) {
      const [b64Part, addrPart] = rest.split('@');
      const decoded = atob(b64Part);
      const colonIdx = decoded.indexOf(':');
      method = decoded.slice(0, colonIdx);
      password = decoded.slice(colonIdx + 1);
      const lastColon = addrPart.lastIndexOf(':');
      server = addrPart.slice(0, lastColon);
      if (server.startsWith('[') && server.endsWith(']')) server = server.slice(1, -1);
      port = parseInt(addrPart.slice(lastColon + 1)) || 8388;
    } else {
      const decoded = atob(rest);
      const [cred, addr] = decoded.split('@');
      const cIdx = cred.indexOf(':');
      method = cred.slice(0, cIdx);
      password = cred.slice(cIdx + 1);
      const lastColon = addr.lastIndexOf(':');
      server = addr.slice(0, lastColon);
      if (server.startsWith('[') && server.endsWith(']')) server = server.slice(1, -1);
      port = parseInt(addr.slice(lastColon + 1)) || 8388;
    }

    return {
      name,
      type: 'ss',
      server,
      port,
      cipher: method,
      password,
      udp: true,
    };
  } catch (e) {
    console.error('SS 解析失败:', e);
    return null;
  }
}

/**
 * 解析 Hysteria2 链接
 * 格式: hysteria2://password@server:port?params#name
 * 或:   hysteria2://server:port?auth=password&params#name
 */
function parseHysteria2(uri) {
  try {
    const url = new URL(uri);
    const name = decodeURIComponent(url.hash?.slice(1) || 'Hysteria2 节点');
    const params = url.searchParams;
    const password = url.username || params.get('auth') || '';

    const proxy = {
      name,
      type: 'hysteria2',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      password,
      udp: true,
    };

    if (params.get('sni')) proxy.sni = params.get('sni');
    if (params.get('insecure') === '1' || params.get('insecure') === 'true') {
      proxy.skip_cert_verify = true;
    }
    if (params.get('mport')) proxy.ports = params.get('mport');
    if (params.get('obfs')) {
      proxy.obfs = { type: params.get('obfs') };
      if (params.get('obfs-password')) proxy.obfs.password = params.get('obfs-password');
    }
    if (params.get('alpn')) proxy.alpn = params.get('alpn').split(',').map(s => s.trim());

    return proxy;
  } catch (e) {
    console.error('Hysteria2 解析失败:', e);
    return null;
  }
}

/**
 * 解析 TUIC v5 链接
 * 格式: tuic://uuid:password@server:port?params#name
 */
function parseTuic(uri) {
  try {
    const url = new URL(uri);
    const name = decodeURIComponent(url.hash?.slice(1) || 'TUIC 节点');
    const params = url.searchParams;

    const proxy = {
      name,
      type: 'tuic',
      server: url.hostname,
      port: parseInt(url.port) || 443,
      uuid: url.username,
      password: url.password || '',
      udp: true,
    };

    if (params.get('congestion_control')) proxy.congestion_controller = params.get('congestion_control');
    if (params.get('alpn')) proxy.alpn = params.get('alpn').split(',').map(s => s.trim());
    if (params.get('sni')) proxy.sni = params.get('sni');
    if (params.get('allow_insecure') === '1' || params.get('allow_insecure') === 'true') {
      proxy.skip_cert_verify = true;
    }
    if (params.get('disable_sni') === '1' || params.get('disable_sni') === 'true') {
      proxy.disable_sni = true;
    }
    if (params.get('reduce_rtt') === '1' || params.get('reduce_rtt') === 'true') {
      proxy.reduce_rtt = true;
    }
    if (params.get('udp_relay_mode')) proxy.udp_relay_mode = params.get('udp_relay_mode');

    return proxy;
  } catch (e) {
    console.error('TUIC 解析失败:', e);
    return null;
  }
}

/** 路由分发：根据前缀匹配协议类型 */
function parseLink(link) {
  const trimmed = link.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('vmess://')) return parseVmess(trimmed);
  if (trimmed.startsWith('vless://')) return parseVless(trimmed);
  if (trimmed.startsWith('trojan://')) return parseTrojan(trimmed);
  if (trimmed.startsWith('ss://')) return parseSS(trimmed);
  if (trimmed.startsWith('hysteria2://') || trimmed.startsWith('hy2://')) return parseHysteria2(trimmed);
  if (trimmed.startsWith('tuic://')) return parseTuic(trimmed);
  return null;
}

// ======================== UI 逻辑 ========================

/** 解析手动粘贴的链接，标记来源后加入列表（不查国家，统一查） */
function parseAllLinks() {
  const input = document.getElementById('linkInput').value;
  const importName = document.getElementById('manualImportName').value.trim() || '手动';
  const lines = input.split('\n').filter(line => line.trim());
  const newProxies = [];

  for (const line of lines) {
    const proxy = parseLink(line);
    if (proxy) {
      proxy._source = importName;
      proxy._origName = proxy.name;
      proxy._checked = false;
      newProxies.push(proxy);
    }
  }

  if (newProxies.length === 0) {
    showToast('linkStatus', parsedProxies.length === 0 ? '未识别到有效节点链接' : '未识别到新的有效节点链接', 'warning');
    return;
  }

  // 合并去重（按 server+port 去重）
  mergeProxies(newProxies);
  showToast('linkStatus', `已导入 ${newProxies.length} 个节点（总计 ${parsedProxies.length} 个），点击「检测国家」统一查询`, 'info');
  renderProxyPreview();
  updateProxySelects();
}

/**
 * 从文本中提取代理节点（YAML proxies 或逐行代理链接）
 */
function extractProxiesFromText(txt) {
  let result = [];
  try {
    const cfg = jsyaml.load(txt);
    if (cfg && cfg.proxies && Array.isArray(cfg.proxies)) {
      return cfg.proxies;
    }
  } catch (_) {}

  const lines = txt.split('\n').filter(l => l.trim());
  for (let i = 0; i < lines.length; i++) {
    const p = parseLink(lines[i]);
    if (p) result.push(p);
  }
  return result;
}

/**
 * 抓取单个订阅 URL 并返回解析出的代理节点
 */
async function fetchOneSubscription(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error('HTTP ' + resp.status);
  let rawText = await resp.text();

  if (!rawText || rawText.trim().length === 0) {
    throw new Error('返回空内容');
  }

  let proxies = extractProxiesFromText(rawText);

  if (proxies.length === 0) {
    try {
      const decoded = atob(rawText.trim());
      if (decoded) {
        proxies = extractProxiesFromText(decoded);
      }
    } catch (_) {}
  }

  return proxies;
}

// ======================== 国家检测（GeoIP + 名称提取） ========================

// 国家名称缓存: server -> 中文国名
const countryCache = {};

// 旗帜 emoji → 中文国名
const FLAG_TO_COUNTRY = {
  '🇭🇰': '香港', '🇺🇸': '美国', '🇯🇵': '日本', '🇳🇱': '荷兰',
  '🇷🇺': '俄罗斯', '🇩🇪': '德国', '🇨🇭': '瑞士', '🇫🇷': '法国',
  '🇬🇧': '英国', '🇸🇪': '瑞典', '🇧🇬': '保加利亚', '🇦🇹': '奥地利',
  '🇮🇪': '爱尔兰', '🇹🇷': '土耳其', '🇭🇺': '匈牙利', '🇰🇷': '韩国',
  '🇨🇳': '中国', '🇨🇦': '加拿大', '🇦🇺': '澳大利亚', '🇦🇪': '阿联酋',
  '🇮🇳': '印度', '🇮🇩': '印尼', '🇧🇷': '巴西', '🇦🇷': '阿根廷',
  '🇨🇱': '智利', '🇸🇬': '新加坡', '🇲🇾': '马来西亚', '🇹🇭': '泰国',
  '🇻🇳': '越南', '🇵🇭': '菲律宾', '🇮🇹': '意大利', '🇪🇸': '西班牙',
  '🇳🇴': '挪威', '🇩🇰': '丹麦', '🇫🇮': '芬兰', '🇧🇪': '比利时',
  '🇵🇱': '波兰', '🇨🇿': '捷克', '🇷🇴': '罗马尼亚', '🇿🇦': '南非',
  '🇲🇴': '澳门',
};

// 关键字 → 中文国名
const KEYWORD_TO_COUNTRY = {
  'hong kong': '香港', 'usa': '美国', 'japan': '日本', 'netherlands': '荷兰',
  'russia': '俄罗斯', 'germany': '德国', 'switzerland': '瑞士', 'france': '法国',
  'united kingdom': '英国', 'sweden': '瑞典', 'bulgaria': '保加利亚', 'austria': '奥地利',
  'ireland': '爱尔兰', 'turkey': '土耳其', 'hungary': '匈牙利', 'korea': '韩国',
  'taiwan': '台湾', 'canada': '加拿大', 'australia': '澳大利亚',
  'united arab emirates': '阿联酋', 'india': '印度', 'indonesia': '印尼',
  'brazil': '巴西', 'argentina': '阿根廷', 'chile': '智利', 'singapore': '新加坡',
  'malaysia': '马来西亚', 'thailand': '泰国', 'vietnam': '越南',
  'philippines': '菲律宾', 'italy': '意大利', 'spain': '西班牙',
  'norway': '挪威', 'denmark': '丹麦', 'finland': '芬兰', 'belgium': '比利时',
  'poland': '波兰', 'seattle': '美国', 'los angeles': '美国', 'san jose': '美国',
  'sydney': '澳大利亚', 'moscow': '俄罗斯', 'st. petersburg': '俄罗斯',
  'london': '英国', 'amsterdam': '荷兰', 'frankfurt': '德国',
};

/** 从节点名称提取国家（YAML 节点通常有国旗和地区名） */
function extractCountryFromName(name) {
  // 1. 检查旗帜 emoji
  for (const [flag, cn] of Object.entries(FLAG_TO_COUNTRY)) {
    if (name.includes(flag)) return cn;
  }
  // 2. 检查关键字
  const lower = name.toLowerCase();
  for (const [kw, cn] of Object.entries(KEYWORD_TO_COUNTRY)) {
    if (lower.includes(kw)) return cn;
  }
  return null;
}

/** 查询节点服务器的归属国家（带缓存） */
async function lookupCountry(server) {
  if (countryCache[server]) return countryCache[server];
  try {
    const resp = await fetch(`http://ip-api.com/json/${encodeURIComponent(server)}?fields=country`);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    const cn = COUNTRY_MAP[data.country] || data.country || '未知';
    countryCache[server] = cn;
    return cn;
  } catch (e) {
    console.warn('GeoIP 查询失败:', server, e.message);
    countryCache[server] = '未知';
    return '未知';
  }
}
// ======================== 订阅行管理 ========================

let subRowCounter = 0;

/** 创建一行订阅输入 */
function createSubRow(name, url) {
  subRowCounter++;
  const row = document.createElement('div');
  row.className = 'sub-row';
  row.innerHTML = `
    <input class="sub-name" type="text" value="${escapeHtml(name)}" placeholder="订阅名">
    <input class="sub-url" type="text" value="${escapeHtml(url)}" placeholder="https://...">
    <button class="btn-remove" title="移除">×</button>
  `;
  row.querySelector('.btn-remove').addEventListener('click', () => {
    row.remove();
    saveSubs();
  });
  row.querySelector('input').addEventListener('input', saveSubs);
  row.querySelectorAll('input').forEach(inp => inp.addEventListener('input', saveSubs));
  return row;
}

/** 获取当前所有订阅 */
function getAllSubs() {
  const rows = document.querySelectorAll('#subList .sub-row');
  const subs = [];
  rows.forEach(row => {
    const name = row.querySelector('.sub-name').value.trim();
    const url = row.querySelector('.sub-url').value.trim();
    if (url) subs.push({ name: name || `订阅${subs.length + 1}`, url });
  });
  return subs;
}

/** 保存订阅列表到 storage */
function saveSubs() {
  const subs = getAllSubs();
  chrome.storage.local.set({ subList: subs });
}

/** 添加一行 */
function addSubRow(name, url) {
  const list = document.getElementById('subList');
  const row = createSubRow(name || '', url || '');
  list.appendChild(row);
  saveSubs();
}

// ======================== 抓取订阅 ========================

/**
 * 从所有订阅行抓取代理节点、检测国家、合并去重
 */
async function fetchSubscription() {
  const subs = getAllSubs();
  if (subs.length === 0) {
    showToast('subFetchStatus', '请至少添加一个订阅链接', 'warning');
    return;
  }

  saveSubs();
  const el = document.getElementById('subFetchStatus');

  let allNewProxies = [];
  let successCount = 0;
  let failCount = 0;

  for (let i = 0; i < subs.length; i++) {
    const sub = subs[i];
    const label = subs.length > 1 ? `[${i + 1}/${subs.length}]` : '';
    el.innerHTML = `<span class="toast toast-info">${label} ${sub.name} 正在抓取...</span>`;

    try {
      let proxies = await fetchOneSubscription(sub.url);
      if (proxies.length === 0) {
        failCount++;
        console.warn('订阅未识别到节点:', sub.name);
        continue;
      }

      // 标记来源，暂不查国家（统一查）
      for (const p of proxies) {
        p._source = sub.name;
        p._origName = p.name;
        p._checked = false;
      }

      allNewProxies = allNewProxies.concat(proxies);
      successCount++;
    } catch (e) {
      failCount++;
      console.error('抓取失败:', sub.name, e.message);
    }
  }

  if (allNewProxies.length === 0) {
    el.innerHTML = '<span class="toast toast-warning">所有订阅均未能识别到代理节点</span>';
    setTimeout(() => { el.innerHTML = ''; }, 5000);
    return;
  }

  // 合并
  mergeProxies(allNewProxies);
  renderProxyPreview();
  updateProxySelects();

  const unchecked = parsedProxies.filter(p => p._source && !p._checked).length;
  let msg = `${successCount} 个订阅抓取完成，共 ${parsedProxies.length} 个节点`;
  if (unchecked > 0) msg += `，${unchecked} 个待查国家`;
  const type = failCount > 0 ? 'warning' : 'success';
  el.innerHTML = `<span class="toast toast-${type}">${msg}</span>`;
  setTimeout(() => { el.innerHTML = ''; }, 5000);
}

/** 合并代理列表（按 server+port 去重） */
function mergeProxies(newProxies) {
  const seen = new Set(parsedProxies.map(p => `${p.server}:${p.port}`));
  const unique = newProxies.filter(p => {
    const key = `${p.server}:${p.port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  parsedProxies = [...parsedProxies, ...unique];
}

/** 对已导入但未查国家的节点统一检测国家并重命名 */
async function detectAndRenameAll() {
  const unchecked = parsedProxies.filter(p => p._source && !p._checked);
  if (unchecked.length === 0) {
    showToast('subFetchStatus', '所有节点已检测过国家', 'info');
    return;
  }

  const btn = document.getElementById('btnDetectCountry');
  btn.disabled = true;
  btn.textContent = '检测中...';

  const el = document.getElementById('subFetchStatus');
  el.innerHTML = `<span class="toast toast-info">正在检测 ${unchecked.length} 个节点国家...</span>`;

  // 收集唯一 server
  const servers = [...new Set(unchecked.map(p => p.server))];
  for (let i = 0; i < servers.length; i++) {
    el.innerHTML = `<span class="toast toast-info">检测国家 [${i + 1}/${servers.length}]...</span>`;
    await lookupCountry(servers[i]);
    if (i < servers.length - 1) await new Promise(r => setTimeout(r, 200));
  }

  // 重命名：基于 _origName（原始名称），避免重复叠加
  for (const p of unchecked) {
    const country = countryCache[p.server] || '未知';
    const baseName = p._origName || p.name;
    p.name = `${p._source}-${country}-${baseName}`;
    p._origName = baseName;  // 保存基准名，后续点击不会叠加
    p._checked = true;
  }

  renderProxyPreview();
  updateProxySelects();
  el.innerHTML = `<span class="toast toast-success">完成！已为 ${unchecked.length} 个节点标注国家</span>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);

  btn.disabled = false;
  btn.textContent = '检测国家并重命名';
}

/** 渲染节点预览标签 */
function renderProxyPreview() {
  const container = document.getElementById('proxyPreview');
  const counter = document.getElementById('proxyCount');
  if (parsedProxies.length === 0) {
    container.innerHTML = '';
    counter.textContent = '未导入节点';
    return;
  }
  const unchecked = parsedProxies.filter(p => p._source && !p._checked).length;
  let status = `共 ${parsedProxies.length} 个节点`;
  if (unchecked > 0) status += `（${unchecked} 个待查国家）`;
  counter.textContent = status;
  // 只显示前 30 个
  const show = parsedProxies.slice(0, 30);
  let html = show.map(p => {
    const tag = p._source && !p._checked ? ' ⏳' : '';
    return `<span class="proxy-badge"><span class="type">${p.type.toUpperCase()}</span> ${escapeHtml(p.name)}${tag}</span>`;
  }).join('');
  if (parsedProxies.length > 30) {
    html += `<span class="proxy-badge">... 还有 ${parsedProxies.length - 30} 个</span>`;
  }
  container.innerHTML = html;
}

/** 更新下拉选择框 */
function updateProxySelects() {
  const names = parsedProxies.map(p => p.name);
  [document.getElementById('relayProxy'), document.getElementById('exitProxy')].forEach(sel => {
    const current = sel.value;
    sel.innerHTML = '<option value="">-- 选择节点 --</option>' +
      names.map(n => `<option value="${escapeHtml(n)}" ${n === current ? 'selected' : ''}>${escapeHtml(n)}</option>`).join('');
  });
}

/** 切换监听器设置可见性 */
function toggleListenerSettings() {
  const checked = document.getElementById('enableListeners').checked;
  document.getElementById('listenerSettings').style.display = checked ? '' : 'none';
}

/** Toast 提示 */
function showToast(elId, msg, type) {
  const el = document.getElementById(elId);
  el.innerHTML = `<span class="toast toast-${type}">${msg}</span>`;
  setTimeout(() => { el.innerHTML = ''; }, 4000);
}

// ======================== 配置生成 ========================

function generateConfig() {
  const yamlText = document.getElementById('yamlInput').value.trim();
  let config = {};

  // Step 1: 解析基础 YAML（如果有，保留所有原有字段）
  if (yamlText) {
    try {
      config = jsyaml.load(yamlText) || {};
      if (typeof config !== 'object' || Array.isArray(config)) {
        showToast('genStatus', 'YAML 格式错误：顶层必须是映射', 'error');
        return;
      }
    } catch (e) {
      showToast('genStatus', `YAML 解析失败: ${e.message}`, 'error');
      return;
    }
  }

  if (parsedProxies.length === 0) {
    showToast('genStatus', '请先解析节点链接或抓取订阅', 'warning');
    return;
  }

  // Step 2: 替换代理列表（清理内部字段 _source, _checked）
  config.proxies = parsedProxies.map(p => {
    const { _source, _checked, _origName, ...clean } = p;
    return clean;
  });

  // 模式 B — 多出口监听器（先处理，因为端口号要写进节点名）
  const enableListeners = document.getElementById('enableListeners').checked;

  if (enableListeners) {
    const lType = document.getElementById('listenerType').value;
    const startPort = parseInt(document.getElementById('startPort').value) || 8000;
    const lAddr = document.getElementById('listenAddr').value || '127.0.0.1';

    // 将监听端口号插入节点名：来源-国家-原名 → 来源-国家-端口-原名
    config.proxies = config.proxies.map((p, i) => {
      const parts = p.name.split('-');
      if (parts.length >= 2) {
        const source = parts[0];
        const country = parts[1];
        const rest = parts.slice(2).join('-');
        const port = startPort + i;
        return { ...p, name: `${source}-${country}-${port}-${rest}` };
      }
      return p;
    });

    config.listeners = config.proxies.map((p, i) => ({
      name: `${p.type}-${p.name}`,
      type: lType,
      address: lAddr,
      port: startPort + i,
      proxy: p.name,
    }));

    // 仅在原配置没有 dns 时补充默认 dns 配置
    if (!config.dns) {
      config.dns = {
        enable: true,
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        'default-nameserver': [
          '114.114.114.114',
          '223.5.5.5',
        ],
        'fake-ip-filter': [
          '*.lan',
          'localhost.ptlogin2.qq.com',
        ],
        nameserver: [
          'https://doh.pub/dns-query',
          'https://dns.alidns.com/dns-query',
        ],
        fallback: [
          'https://cloudflare-dns.com/dns-query',
          'https://dns.google/dns-query',
        ],
        'fallback-filter': {
          geoip: true,
          geoip_code: 'CN',
        },
      };
    }
  }

  // 更新 proxy-groups，保持原有组名
  const proxyNames = config.proxies.map(p => p.name);
  if (config['proxy-groups'] && config['proxy-groups'].length > 0) {
    for (const g of config['proxy-groups']) {
      g.proxies = proxyNames;
    }
  } else {
    config['proxy-groups'] = [{ name: 'Proxy', type: 'select', proxies: proxyNames }];
    config.rules = ['MATCH,Proxy'];
  }

  // 模式 A — 链式代理
  const relayName = document.getElementById('relayProxy').value;
  const exitName = document.getElementById('exitProxy').value;

  if (relayName && exitName) {
    if (relayName === exitName) {
      showToast('genStatus', '跳板节点和出口节点不能相同', 'error');
      return;
    }
    config.proxies = config.proxies.map(p => {
      if (p.name === exitName) {
        return { ...p, 'dialer-proxy': relayName };
      }
      return p;
    });
    showToast('genStatus', `链式代理已设置: ${exitName} → ${relayName}`, 'success');
  }

  // 输出 YAML（noCompatMode: false 保持 YAML 1.1 兼容，Go 解析器需要）
  try {
    const output = jsyaml.dump(config, { lineWidth: -1, quotingType: '"' });
    document.getElementById('outputYaml').value = output;
    showToast('genStatus', `配置生成成功！${enableListeners ? '已包含 DNS fake-ip 配置和 ' + config.proxies.length + ' 个监听器' : ''}`, 'success');
  } catch (e) {
    showToast('genStatus', `YAML 序列化失败: ${e.message}`, 'error');
  }
}

/** 复制到剪贴板 */
async function copyToClipboard() {
  const text = document.getElementById('outputYaml').value;
  if (!text) {
    showToast('exportStatus', '没有可复制的内容，请先生成配置', 'warning');
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    showToast('exportStatus', '配置已复制到剪贴板', 'success');
  } catch {
    const ta = document.getElementById('outputYaml');
    ta.select();
    document.execCommand('copy');
    showToast('exportStatus', '配置已复制到剪贴板', 'success');
  }
}

/** 保存为 .yaml 文件 */
function saveToFile() {
  const text = document.getElementById('outputYaml').value;
  if (!text) {
    showToast('exportStatus', '没有可保存的内容，请先生成配置', 'warning');
    return;
  }

  // 优先使用 Chrome Downloads API
  if (chrome.downloads) {
    const blob = new Blob([text], { type: 'application/x-yaml' });
    const url = URL.createObjectURL(blob);
    chrome.downloads.download({
      url: url,
      filename: 'clash-meta-config.yaml',
      saveAs: true,
    }, () => {
      URL.revokeObjectURL(url);
      showToast('exportStatus', '文件下载已开始', 'success');
    });
  } else {
    // 降级方案：创建链接点击下载
    const blob = new Blob([text], { type: 'application/x-yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'clash-meta-config.yaml';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('exportStatus', '文件已下载: clash-meta-config.yaml', 'success');
  }
}

// ======================== 辅助函数 ========================
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ======================== 事件绑定 ========================
document.addEventListener('DOMContentLoaded', () => {
  // 按钮事件
  document.getElementById('btnFetchSub').addEventListener('click', fetchSubscription);
  document.getElementById('btnAddSub').addEventListener('click', () => addSubRow());
  document.getElementById('btnParseLinks').addEventListener('click', parseAllLinks);
  document.getElementById('btnGenerate').addEventListener('click', generateConfig);
  document.getElementById('btnCopy').addEventListener('click', copyToClipboard);
  document.getElementById('btnDownload').addEventListener('click', saveToFile);
  document.getElementById('btnDetectCountry').addEventListener('click', detectAndRenameAll);
  document.getElementById('btnClearProxies').addEventListener('click', () => {
    parsedProxies = [];
    baseConfig = null;
    renderProxyPreview();
    updateProxySelects();
    document.getElementById('outputYaml').value = '';
    showToast('linkStatus', '已清除所有节点', 'info');
  });

  // 监听器开关
  document.getElementById('enableListeners').addEventListener('change', toggleListenerSettings);

  // YAML 输入变化时自动解析（保留原有代理名称，不做国家重命名）
  document.getElementById('yamlInput').addEventListener('change', () => {
    const yamlText = document.getElementById('yamlInput').value.trim();
    if (!yamlText) { baseConfig = null; return; }
    try {
      baseConfig = jsyaml.load(yamlText) || {};
      if (baseConfig.proxies && Array.isArray(baseConfig.proxies)) {
        const existingNames = new Set(parsedProxies.map(p => p.name));
        const fromYaml = baseConfig.proxies.filter(p => {
          if (!p.name) return false;
          if (existingNames.has(p.name)) return false;
          existingNames.add(p.name);
          return true;
        });
        if (fromYaml.length > 0) {
          // YAML 节点从原名提取国家（国旗/地区名），不查 GeoIP（服务器物理位置不准确）
          const importName = document.getElementById('manualImportName').value.trim() || 'YAML';
          for (const p of fromYaml) {
            const detected = extractCountryFromName(p.name);
            p._source = importName;
            p._origName = p.name;
            if (detected) {
              p.name = `${importName}-${detected}-${p.name}`;
              p._checked = true;
            } else {
              p._checked = false;
            }
          }
          mergeProxies(fromYaml);
          renderProxyPreview();
          updateProxySelects();
          const detected = fromYaml.filter(p => p._checked).length;
          showToast('linkStatus', `从 YAML 中读取 ${fromYaml.length} 个节点（${detected} 个识别出国家，${fromYaml.length - detected} 个待查）`, 'success');
        }
      }
    } catch {
      baseConfig = null;
    }
  });

  // 恢复已保存的订阅列表（持久化）
  chrome.storage.local.get(['subList', 'linkInput', 'yamlInput', 'importName'], (result) => {
    const subs = result.subList;
    if (subs && subs.length > 0) {
      subs.forEach(s => addSubRow(s.name, s.url));
    } else {
      addSubRow('', '');
    }
    if (result.linkInput) document.getElementById('linkInput').value = result.linkInput;
    if (result.yamlInput) document.getElementById('yamlInput').value = result.yamlInput;
    if (result.importName) document.getElementById('manualImportName').value = result.importName;
  });

  // 自动保存：手动粘贴链接、YAML 配置、导入名称
  const autoSaveInputs = () => {
    chrome.storage.local.set({
      linkInput: document.getElementById('linkInput').value,
      yamlInput: document.getElementById('yamlInput').value,
      importName: document.getElementById('manualImportName').value,
    });
  };
  document.getElementById('linkInput').addEventListener('input', autoSaveInputs);
  document.getElementById('yamlInput').addEventListener('input', autoSaveInputs);
  document.getElementById('manualImportName').addEventListener('input', autoSaveInputs);
});
