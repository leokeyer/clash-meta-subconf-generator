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

/** 解析所有链接并更新全局 parsedProxies */
function parseAllLinks() {
  const input = document.getElementById('linkInput').value;
  const lines = input.split('\n').filter(line => line.trim());
  const newProxies = [];

  for (const line of lines) {
    const proxy = parseLink(line);
    if (proxy) newProxies.push(proxy);
  }

  if (newProxies.length > 0) {
    const existingNames = new Set(parsedProxies.map(p => p.name));
    const uniqueNew = newProxies.filter(p => {
      if (existingNames.has(p.name)) return false;
      existingNames.add(p.name);
      return true;
    });
    parsedProxies = [...parsedProxies, ...uniqueNew];
    showToast('linkStatus', `解析成功，新增 ${uniqueNew.length} 个节点（总计 ${parsedProxies.length} 个）`, 'success');
  } else {
    if (parsedProxies.length === 0) {
      showToast('linkStatus', '未识别到有效节点链接，请检查格式', 'warning');
    } else {
      showToast('linkStatus', '未识别到新的有效节点链接', 'warning');
    }
  }

  renderProxyPreview();
  updateProxySelects();
  if (baseConfig) {
    baseConfig.proxies = parsedProxies;
  }
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

// ======================== GeoIP 国家检测 ========================

// 国家名称缓存: server -> 中文国名
const countryCache = {};

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

/**
 * 为一批代理节点检测国家并重命名
 * 格式: 订阅名-国家-原节点名
 */
async function tagProxiesWithCountry(proxies, subName) {
  const el = document.getElementById('subFetchStatus');
  // 收集所有唯一的 server
  const uniqueServers = [...new Set(proxies.map(p => p.server))];

  // 逐个查询（ip-api 免费版不支持批量域名查询）
  for (let i = 0; i < uniqueServers.length; i++) {
    el.innerHTML = `<span class="toast toast-info">${subName} 正在检测节点国家 [${i + 1}/${uniqueServers.length}]...</span>`;
    await lookupCountry(uniqueServers[i]);
    // 控制请求频率（免费版限制 45/min）
    if (i < uniqueServers.length - 1) {
      await new Promise(r => setTimeout(r, 200));
    }
  }

  // 重命名
  for (const p of proxies) {
    const country = countryCache[p.server] || '未知';
    p.name = `${subName}-${country}-${p.name}`;
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

      // 检测国家并重命名
      el.innerHTML = `<span class="toast toast-info">${label} ${sub.name} 正在检测国家...</span>`;
      await tagProxiesWithCountry(proxies, sub.name);

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

  // 合并去重（以新的格式化名称为准）
  const existingNames = new Set(parsedProxies.map(p => p.name));
  const uniqueNew = allNewProxies.filter(p => {
    if (!p.name) return false;
    if (existingNames.has(p.name)) return false;
    existingNames.add(p.name);
    return true;
  });

  parsedProxies = parsedProxies.concat(uniqueNew);
  renderProxyPreview();
  updateProxySelects();

  let msg = `完成！${successCount} 个成功`;
  if (failCount > 0) msg += `，${failCount} 个失败`;
  msg += `，共 ${uniqueNew.length} 个节点`;
  const type = failCount > 0 ? 'warning' : 'success';
  el.innerHTML = `<span class="toast toast-${type}">${msg}</span>`;
  setTimeout(() => { el.innerHTML = ''; }, 6000);
}

/** 渲染节点预览标签 */
function renderProxyPreview() {
  const container = document.getElementById('proxyPreview');
  if (parsedProxies.length === 0) {
    container.innerHTML = '';
    return;
  }
  container.innerHTML = parsedProxies.map(p =>
    `<span class="proxy-badge"><span class="type">${p.type.toUpperCase()}</span> ${escapeHtml(p.name)}</span>`
  ).join('');
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
  config.proxies = parsedProxies;

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

  // 模式 B — 多出口监听器
  const enableListeners = document.getElementById('enableListeners').checked;

  if (enableListeners) {
    const lType = document.getElementById('listenerType').value;
    const startPort = parseInt(document.getElementById('startPort').value) || 8000;
    const lAddr = document.getElementById('listenAddr').value || '127.0.0.1';

    config.listeners = config.proxies.map((p, i) => ({
      name: `${p.type}-${p.name}`,
      type: lType,
      address: lAddr,
      port: startPort + i,
      proxy: p.name,
    }));

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

  // proxy-groups — Clash 必需的路由选择组
  const proxyNames = config.proxies.map(p => p.name);
  config['proxy-groups'] = [
    {
      name: 'Proxy',
      type: 'select',
      proxies: proxyNames,
    },
  ];

  // rules — Clash 必需的流量匹配规则
  config.rules = [
    'MATCH,Proxy',
  ];

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

  // 监听器开关
  document.getElementById('enableListeners').addEventListener('change', toggleListenerSettings);

  // YAML 输入变化时自动解析
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
          parsedProxies = [...parsedProxies, ...fromYaml];
          renderProxyPreview();
          updateProxySelects();
          showToast('linkStatus', `从 YAML 中读取到 ${fromYaml.length} 个节点（总计 ${parsedProxies.length} 个）`, 'info');
        }
      }
    } catch {
      baseConfig = null;
    }
  });

  // 恢复已保存的订阅列表（持久化）
  chrome.storage.local.get('subList', (result) => {
    const subs = result.subList;
    if (subs && subs.length > 0) {
      subs.forEach(s => addSubRow(s.name, s.url));
    } else {
      // 首次使用，预置一行空白
      addSubRow('', '');
    }
  });
});
