(() => {
'use strict';

// ---------- утилиты ----------
const $ = (id) => document.getElementById(id);
const ESC = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
// SSID и вендоры приходят из эфира и не под нашим контролем: весь динамический текст - только через esc().
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ESC[c]);
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

function hueOf(str) {
  // FNV-1a + финализатор murmur3: похожие SSID получают далёкие оттенки
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) h = Math.imul(h ^ str.charCodeAt(i), 0x01000193);
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return (h >>> 0) % 360;
}

// ---------- настройки вида (живут в браузере, приложение работает и без них) ----------
const THEMES = [
  {id: 'auto', name: 'Как в системе', c: ['#eef1f4', '#151b21', '#0a6c8f']},
  {id: 'light', name: 'Светлая', c: ['#eef1f4', '#ffffff', '#0a6c8f']},
  {id: 'dark', name: 'Тёмная', dark: 1, c: ['#0e1216', '#151b21', '#4fc3f0']},
  {id: 'nord', name: 'Nord', dark: 1, c: ['#2e3440', '#3b4252', '#88c0d0']},
  {id: 'solar', name: 'Solarized', dark: 1, c: ['#002b36', '#073642', '#3fcfc3']},
  {id: 'paper', name: 'Тёплая бумага', c: ['#efe8da', '#faf6ec', '#2d6a52']},
  {id: 'contrast', name: 'Контрастная', dark: 1, c: ['#000000', '#161616', '#ffd60a']},
];
const P = {theme: 'auto', density: 'normal', cols: null, panelH: null, tab: 'channels', group: false, sigMode: 'lines', sigColor: 'level', heatAll: false, v: 0};
try { Object.assign(P, JSON.parse(localStorage.getItem('wd_prefs') || '{}')); } catch (e) { /* без сохранения */ }
// Порт у приложения каждый раз новый, а localStorage привязан к адресу, поэтому настройки ещё и
// отправляются программе: она хранит их в файле и возвращает при следующем запуске.
let prefTimer = null;
function savePrefs() {
  try { localStorage.setItem('wd_prefs', JSON.stringify(P)); } catch (e) { /* без сохранения */ }
  clearTimeout(prefTimer);
  prefTimer = setTimeout(() => { api('/api/prefs', P).catch(() => {}); }, 400);
}

let DARK = false;
const mq = window.matchMedia('(prefers-color-scheme: dark)');
function applyTheme() {
  const id = P.theme === 'auto' ? (mq.matches ? 'dark' : 'light') : P.theme;
  const t = THEMES.find((x) => x.id === id) || THEMES[1];
  DARK = !!t.dark;
  document.documentElement.dataset.theme = t.id;
  document.documentElement.dataset.density = P.density;
}
applyTheme();

const ssidColor = (s) => `hsl(${hueOf(s)} ${DARK ? '70% 64%' : '62% 42%'})`;
const seriesColor = (i) => `hsl(${(i * 47 + 210) % 360} ${DARK ? '72% 66%' : '65% 44%'})`;

// Сигнал везде в одной шкале: от красного (плохо) к зелёному (хорошо). Те же точки, что на карте обхода и в отчётах.
const SIG_STOPS = [[-85, 0], [-75, 25], [-67, 55], [-60, 95], [-50, 130]];
function sigHue(r) {
  if (r <= SIG_STOPS[0][0]) return SIG_STOPS[0][1];
  for (let k = 1; k < SIG_STOPS.length; k++) {
    const [a, ha] = SIG_STOPS[k - 1], [b, hb] = SIG_STOPS[k];
    if (r <= b) return Math.round(ha + (hb - ha) * (r - a) / (b - a));
  }
  return SIG_STOPS[SIG_STOPS.length - 1][1];
}
// текст темнее заливки: жёлто-зелёный на белом иначе не читается
const sigText = (r) => `hsl(${sigHue(r)} ${DARK ? '75% 62%' : '80% 30%'})`;
const sigFill = (r, a) => `hsl(${sigHue(r)} ${DARK ? '68% 50%' : '72% 44%'}${a == null ? '' : ' / ' + a})`;
const sigSpan = (r, suffix) => r == null ? '—' : `<b class="sig" style="color:${sigText(r)}">${r}${suffix || ''}</b>`;
// зоны качества для фона графиков: [верх, низ, подпись]
const SIG_ZONES = [[-30, -50, 'отлично'], [-50, -60, 'хорошо'], [-60, -67, 'рабочий'], [-67, -75, 'слабый'], [-75, -85, 'плохо'], [-85, -100, 'на грани']];

// Фон по уровню и вертикальный градиент для линий: цвет линии в точке = цвет её уровня
function sigBackdrop(id, y, x0, x1) {
  const top = y(-30), bot = y(-100);
  const stops = [-30, -50, -55, -60, -64, -67, -71, -75, -80, -85, -100]
    .map((r) => `<stop offset="${((y(r) - top) / (bot - top)).toFixed(4)}" stop-color="${sigFill(r)}"/>`).join('');
  let g = `<defs><linearGradient id="${id}" gradientUnits="userSpaceOnUse" x1="0" y1="${top}" x2="0" y2="${bot}">${stops}</linearGradient></defs>`;
  for (const [a, b, label] of SIG_ZONES) {
    g += `<rect x="${x0}" y="${y(a).toFixed(1)}" width="${(x1 - x0).toFixed(1)}" height="${(y(b) - y(a)).toFixed(1)}" style="fill:${sigFill((a + b) / 2, DARK ? 0.10 : 0.08)}"><title>${a}…${b} дБм: ${label}</title></rect>`;
  }
  return g;
}
// цвета BSS для полосы под графиком подключения: без красного и зелёного, чтобы не спорить со шкалой сигнала
const LANE_HUES = [215, 275, 190, 300, 240, 200, 260, 285];
const laneColor = (i) => `hsl(${LANE_HUES[i % LANE_HUES.length]} ${DARK ? '60% 66%' : '55% 46%'})`;
const DASHES = ['', '7 4', '2 3', '10 3 2 3', '4 4', '1 2', '12 4', '6 2 2 2 2 2', '3 6', '8 8'];

function sigScaleLegend() {
  const stops = [-90, -85, -75, -67, -60, -50, -40].map((r) => `${sigFill(r)} ${((r + 90) / 50 * 100).toFixed(0)}%`).join(', ');
  return `<span class="sgscale"><span class="mut">слабее</span><span class="sgbar" style="background:linear-gradient(90deg, ${stops})"></span>` +
    '<span class="mut">сильнее</span><span class="sgticks">−90 · −85 · −75 · −67 · −60 · −50 · −40 дБм</span></span>';
}

let TOKEN = new URLSearchParams(location.search).get('t');
try {
  if (TOKEN) sessionStorage.setItem('wd_t', TOKEN); else TOKEN = sessionStorage.getItem('wd_t');
} catch (e) { /* хранилище недоступно */ }
if (location.search) history.replaceState(null, '', location.pathname);

async function api(path, body, raw) {
  const o = {method: body === undefined ? 'GET' : 'POST', headers: {'X-Token': TOKEN || ''}};
  if (body !== undefined) { o.body = JSON.stringify(body); o.headers['Content-Type'] = 'application/json'; }
  const r = await fetch(path, o);
  if (raw) return r;
  let data = null;
  try { data = await r.json(); } catch (e) { /* не JSON */ }
  return {status: r.status, ok: r.ok, data};
}

// ---------- состояние ----------
const OPEN_IE = [45, 48, 61, 191, 192, 255];   // какие IE раскрыты по умолчанию
const TABS = ['channels', 'overview', 'util', 'signal', 'conn', 'survey', 'findings', 'beacon', 'compare'];
const S = {
  data: null, sort: {k: 'rssi', dir: -1}, q: '', onlyFocus: false, minRssi: -200, sec: '',
  bands: {'2.4': true, '5': true, '6': true}, collapsed: new Set(),
  sel: null, hl: new Set(), hlIdx: -1, tab: TABS.includes(P.tab) ? P.tab : 'channels', cb: '2.4',
  sig: '', lastScan: 0, ieOpen: null, ieFor: null,
};

const COLS = [
  {k: 'ssid', t: 'SSID', on: 1, fixed: 1}, {k: 'bssid', t: 'BSSID', on: 1}, {k: 'vendor', t: 'Вендор', on: 1},
  {k: 'band', t: 'ГГц', num: 1, on: 1}, {k: 'channel', t: 'Канал', num: 1, on: 1}, {k: 'width', t: 'Ширина', num: 1, on: 1},
  {k: 'rssi', t: 'RSSI, дБм', num: 1, on: 1}, {k: 'trend', t: 'Тренд', on: 1}, {k: 'rssi_avg', t: 'RSSI мин / ср / макс', num: 1},
  {k: 'seen_pct', t: 'Виден, %', num: 1},
  {k: 'security', t: 'Безопасность', on: 1}, {k: 'akm', t: 'AKM'}, {k: 'ciphers', t: 'Шифры'}, {k: 'pmf', t: 'PMF'},
  {k: 'gen_n', t: 'Wi-Fi', on: 1}, {k: 'streams', t: 'Потоки', num: 1},
  {k: 'mcs', t: 'Макс. MCS', on: 1}, {k: 'rate', t: 'Макс. PHY, Мбит/с', num: 1, on: 1}, {k: 'bss_color', t: 'BSS Color', num: 1},
  {k: 'krv', t: 'k·r·v', on: 1},
  {k: 'util', t: 'Загрузка', num: 1, on: 1}, {k: 'stations', t: 'Станций', num: 1, on: 1},
  {k: 'country', t: 'Страна', on: 1}, {k: 'beacon', t: 'Beacon, TU', num: 1}, {k: 'dtim', t: 'DTIM', num: 1},
  {k: 'quality', t: 'Качество, %', num: 1},
];
function normalizePrefs() {
  if (!Array.isArray(P.cols)) P.cols = COLS.filter((c) => c.on).map((c) => c.k);
  if (!(P.v >= 2)) { if (!P.cols.includes('trend')) P.cols.push('trend'); P.v = 2; }   // колонка появилась в этой версии
  if (P.v < 3) { for (const k of ['mcs', 'rate']) if (!P.cols.includes(k)) P.cols.push(k); P.v = 3; }
}
normalizePrefs();
const shownCols = () => COLS.filter((c) => c.fixed || P.cols.includes(c.k));

function sortVal(b, k) {
  if (k === 'krv') return (b.k ? 1 : 0) + (b.r ? 1 : 0) + (b.v ? 1 : 0);
  if (k === 'band') return parseFloat(b.band);
  if (k === 'trend') { const h = S.data.history[b.bssid] || []; return h.length > 1 ? h[h.length - 1][1] - h[0][1] : 0; }
  if (k === 'mcs') return b.mcs == null ? -1 : b.gen_n * 1000 + b.mcs * 10 + b.nss;
  const v = b[k];
  if (Array.isArray(v)) return v.join(',').toLowerCase();
  if (v == null) return -1e9;
  return typeof v === 'string' ? v.toLowerCase() : v;
}

function secClass(b) {
  const s = b.security;
  if (s === 'Open') return 'open';
  if (s === 'WEP' || s.includes('WPA1') || b.ciphers.includes('TKIP')) return 'legacy';
  if (s.includes('WPA3') || s.includes('OWE')) return 'wpa3';
  if (s.includes('Enterprise')) return 'ent';
  return 'personal';
}
function secMatch(b, f) {
  if (!f) return true;
  const s = b.security;
  if (f === 'open') return s === 'Open';
  if (f === 'legacy') return secClass(b) === 'legacy';
  if (f === 'ent') return s.includes('Enterprise');
  if (f === 'wpa3') return s.includes('WPA3') || s.includes('OWE') || s.includes('2/3');
  return s.includes('Personal');
}

function focusSet() { return new Set(S.data ? S.data.focus : []); }

function visibleBss() {
  if (!S.data) return [];
  const fs = focusSet();
  const q = S.q.trim().toLowerCase();
  let list = S.data.bss.filter((b) => S.bands[b.band] && b.rssi >= S.minRssi && secMatch(b, S.sec));
  if (S.onlyFocus && fs.size) list = list.filter((b) => fs.has(b.ssid));
  if (q) list = list.filter((b) => (b.ssid + ' ' + b.bssid + ' ' + b.vendor + ' ' + b.security).toLowerCase().includes(q));
  const {k, dir} = S.sort;
  return list.sort((a, b) => {
    const x = sortVal(a, k), y = sortVal(b, k);
    if (x < y) return -dir;
    if (x > y) return dir;
    return a.bssid < b.bssid ? -1 : 1;
  });
}

// ---------- таблица ----------

function cell(b, k) {
  switch (k) {
    case 'ssid': {
      const cur = S.data.conn && S.data.conn.current;
      const me = cur && cur.state === 'connected' && cur.bssid === b.bssid ? '<span class="tag me" title="К этой BSS сейчас подключён ноутбук">подключён</span>' : '';
      return `<td><span class="dot" style="background:${ssidColor(b.ssid)}"></span>${esc(b.ssid)}${b.hidden ? '<span class="tag">скрыт</span>' : ''}${me}</td>`;
    }
    case 'bssid': return `<td class="mono">${esc(b.bssid)}${b.random_mac ? '<span class="tag" title="Локально администрируемый MAC">L</span>' : ''}</td>`;
    case 'rssi': {
      const w = clamp((b.rssi + 100) / 70 * 100, 0, 100);
      return `<td class="num"><span class="rssi"><span class="v" style="color:${sigText(b.rssi)}">${b.rssi}</span>` +
        `<span class="meter" style="color:${sigFill(b.rssi)}"><i style="width:${w}%"></i></span></span></td>`;
    }
    case 'mcs': return `<td title="${esc(mcsTitle(b))}">${b.mcs == null ? (b.phy === 'legacy' ? '<span class="mut">legacy</span>' : '') : `${esc(b.phy)} ${b.mcs} <span class="mut">×${b.nss}</span>`}</td>`;
    case 'rate': return `<td class="num" title="${esc(mcsTitle(b))}">${b.rate == null ? '' : Math.round(b.rate)}</td>`;
    case 'bss_color': return `<td class="num">${b.bss_color == null ? '' : b.bss_color}</td>`;
    case 'trend': return spark(b);
    case 'rssi_avg': return `<td class="num">${b.rssi_min} / ${Math.round(b.rssi_avg)} / ${b.rssi_max}</td>`;
    case 'security': return `<td><span class="sec s-${secClass(b)}">${esc(b.security)}</span></td>`;
    case 'akm': case 'ciphers': return `<td>${esc(b[k].join(', '))}</td>`;
    case 'gen_n': return `<td>${esc(b.gen === 'legacy' ? 'legacy' : b.gen.replace('Wi-Fi ', ''))}</td>`;
    case 'krv': {
      const f = (on, l) => on ? `<b>${l}</b>` : `<span class="off">${l}</span>`;
      return `<td class="krv">${f(b.k, 'k')} ${f(b.r, 'r')} ${f(b.v, 'v')}</td>`;
    }
    case 'util': return `<td class="num">${b.util == null ? '' : b.util.toFixed(0) + '%'}</td>`;
    case 'streams': return `<td class="num">${b.streams || ''}</td>`;
    case 'band': case 'channel': case 'width': case 'seen_pct': case 'stations': case 'beacon': case 'dtim': case 'quality':
      return `<td class="num">${b[k] == null ? '' : esc(b[k])}</td>`;
    default: return `<td>${esc(b[k])}</td>`;
  }
}

function mcsTitle(b) {
  if (b.mcs == null) return b.rate ? `legacy, до ${b.rate} Мбит/с` : '';
  return `${b.phy}: MCS 0–${b.mcs}, потоков ${b.nss}, ${b.width} МГц → до ${b.rate} Мбит/с (потолок PHY по beacon, не текущая скорость)`;
}

// Мини-график RSSI за последние сканы. Шкала не уже 6 дБ, чтобы шум ±1-2 дБ не выглядел как скачок.
function spark(b) {
  const pts = (S.data.history[b.bssid] || []).slice(-30);
  if (pts.length < 2) return '<td></td>';
  const W = 66, H = 18, vs = pts.map((p) => p[1]);
  let lo = Math.min(...vs), hi = Math.max(...vs);
  const mn = lo, mx = hi;
  if (hi - lo < 6) { const m = (hi + lo) / 2; lo = m - 3; hi = m + 3; }
  const x = (i) => 2 + i / (pts.length - 1) * (W - 5), y = (v) => 2 + (hi - v) / (hi - lo) * (H - 4);
  const d = vs.map((v, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(v).toFixed(1)).join(' ');
  return `<td><svg class="spark" width="${W}" height="${H}" role="img" aria-label="RSSI за ${pts.length} сканов: от ${mn} до ${mx} дБм">` +
    `<title>за ${pts.length} сканов: от ${mn} до ${mx} дБм</title><path d="${d}"/>` +
    `<circle cx="${x(vs.length - 1).toFixed(1)}" cy="${y(vs[vs.length - 1]).toFixed(1)}" r="2.4" style="fill:${sigFill(vs[vs.length - 1])}"/></svg></td>`;
}

function renderHead() {
  $('thead').innerHTML = shownCols().map((c) => {
    const on = S.sort.k === c.k;
    const arr = on ? `<span class="arr">${S.sort.dir > 0 ? '▲' : '▼'}</span>` : '';
    return `<th data-k="${c.k}" tabindex="0" class="${on ? 'sorted' : ''}${c.num ? ' num' : ''}">${esc(c.t)}${arr}</th>`;
  }).join('');
}

function rowHtml(b, cols, fs) {
  const cls = [b.bssid === S.sel ? 'sel' : '', S.hl.has(b.bssid) ? 'hl' : '', fs.size && !fs.has(b.ssid) ? 'other' : ''].join(' ');
  return `<tr data-b="${esc(b.bssid)}" tabindex="0" class="${cls}">${cols.map((c) => cell(b, c.k)).join('')}</tr>`;
}

function renderTable() {
  const fs = focusSet(), cols = shownCols(), list = visibleBss();
  let html = '';
  if (P.group) {
    const groups = new Map();
    for (const b of list) { if (!groups.has(b.ssid)) groups.set(b.ssid, []); groups.get(b.ssid).push(b); }
    const order = [...groups.entries()].sort((x, y) => Math.max(...y[1].map((b) => b.rssi)) - Math.max(...x[1].map((b) => b.rssi)));
    for (const [ssid, items] of order) {
      const best = Math.max(...items.map((b) => b.rssi));
      const bands = [...new Set(items.map((b) => b.band))].sort().join(' / ');
      const closed = S.collapsed.has(ssid);
      html += `<tr class="grp" data-g="${esc(ssid)}" tabindex="0"><td colspan="${cols.length}">${closed ? '▸' : '▾'} ` +
        `<span class="dot" style="background:${ssidColor(ssid)}"></span>${esc(ssid)}` +
        `<span class="mut">BSS: ${items.length}, диапазоны: ${esc(bands)} ГГц, лучший сигнал ${best} дБм</span></td></tr>`;
      if (!closed) html += items.map((b) => rowHtml(b, cols, fs)).join('');
    }
  } else {
    html = list.map((b) => rowHtml(b, cols, fs)).join('');
  }
  $('tbody').innerHTML = html;
  const total = S.data ? S.data.bss.length : 0;
  $('count').textContent = total ? `показано ${list.length} из ${total}` : '';
  const empty = $('empty');
  if (!S.data || !total) {
    empty.hidden = false;
    empty.textContent = S.data && S.data.scanning ? 'Идёт сканирование…' : 'Данных пока нет. Нажми «Сканировать».';
  } else if (!list.length) {
    empty.hidden = false;
    empty.textContent = 'Под фильтры ничего не попало. Ослабь фильтр по сигналу или защите.';
  } else {
    empty.hidden = true;
  }
}

// ---------- сводка ----------
function renderStrip() {
  const el = $('strip');
  const d = S.data;
  if (!d || !d.bss.length) { el.innerHTML = '<span class="mut">Сводка появится после первого скана.</span>'; return; }
  const cnt = (band) => d.bss.filter((b) => b.band === band).length;
  const ssids = new Set(d.bss.filter((b) => !b.hidden).map((b) => b.ssid)).size;
  const best = d.bss.reduce((a, b) => (b.rssi > a.rssi ? b : a));
  const loaded = d.bss.filter((b) => b.util != null).sort((a, b) => b.util - a.util)[0];
  const c = {critical: 0, warning: 0, info: 0};
  for (const f of d.findings) c[f.severity]++;
  const it = (label, val, extra) => `<span class="it"><span class="mut">${label}</span><b>${val}</b>${extra ? `<span class="mut">${extra}</span>` : ''}</span>`;
  el.innerHTML =
    it('BSS', d.bss.length) + it('SSID', ssids) +
    it('2.4 ГГц', cnt('2.4')) + it('5 ГГц', cnt('5')) + (cnt('6') ? it('6 ГГц', cnt('6')) : '') +
    it('Лучший сигнал', `<span style="color:${sigText(best.rssi)}">${best.rssi}</span>`, 'дБм, ' + esc(best.ssid)) +
    (loaded ? it('Макс. загрузка', loaded.util.toFixed(0) + '%', `канал ${loaded.channel}, ${esc(loaded.ssid)}`) : '') +
    `<button type="button" class="it" data-goto="findings" title="Открыть находки"><span class="mut">Находки</span>` +
    `<b class="bad">${c.critical}</b><b class="mid">${c.warning}</b><b>${c.info}</b></button>`;
}

// ---------- графики ----------
function chartSize(reserve) {
  const pb = $('panelBody');
  return [clamp(pb.clientWidth - 28, 480, 2400), clamp(pb.clientHeight - reserve, 150, 620)];
}
function svgOpen(W, H) { return `<svg class="chart" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img">`; }

function adviceHtml(band) {
  const rows = (S.data.advice || {})[band];
  if (!rows || !rows.length) return '';
  const items = rows.map((r) =>
    `<span class="arow${r.best ? ' best' : ''}"><b>канал ${r.channel}</b>: ${r.count ? `${r.dbm} дБм, BSS ${r.count}, загрузка ${r.util.toFixed(0)}%` : 'соседей не слышно'}` +
    `${r.best ? ' <span class="good">лучший</span>' : ''}${r.busy ? ' <span class="bad">занят</span>' : ''}${r.dfs ? ' <span class="tag">DFS</span>' : ''}</span>`).join('');
  return `<div class="advice"><div class="sub">Свободность каналов, ${band} ГГц</div>${items}` +
    `<div class="note">Ниже дБм, значит свободнее (сумма сигналов соседей на канале). Каналы с загрузкой от 50% идут последними. ` +
    `Учитывается вся полоса соседа: точка 80 МГц занимает четыре канала. Оценка верна для места, где стоит ноутбук.</div></div>`;
}

function renderChannels() {
  const all = S.data.bss;
  const bands = ['2.4', '5', '6'].filter((b) => all.some((x) => x.band === b));
  if (!bands.includes(S.cb)) S.cb = bands[0];
  const seg = `<div class="toolbar"><span class="seg">${bands.map((b) =>
    `<button type="button" data-cb="${b}" class="${b === S.cb ? 'on' : ''}">${b} ГГц</button>`).join('')}</span>` +
    `<span class="mut">Высота показывает уровень сигнала, ширина — занимаемую полосу. Нажми на полосу, чтобы выбрать BSS.</span></div>`;
  const [W, H] = chartSize(170);
  const L = 44, R = 14, T = 14, B = 28;
  const dom = S.cb === '2.4' ? [-2, 16] : S.cb === '5' ? [32, 170] : [0, 234];
  const x = (c) => L + (c - dom[0]) / (dom[1] - dom[0]) * (W - L - R);
  const y = (r) => T + (-30 - clamp(r, -100, -30)) / 70 * (H - T - B);
  const yb = y(-100);
  let g = svgOpen(W, H);
  for (let r = -30; r >= -100; r -= 10) {
    g += `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(r)}" y2="${y(r)}"/><text x="${L - 6}" y="${y(r) + 4}" text-anchor="end">${r}</text>`;
  }
  g += `<line class="axis" x1="${L}" x2="${W - R}" y1="${yb}" y2="${yb}"/>`;
  if (S.cb === '5') {
    g += `<rect class="zone" x="${x(50)}" y="${T}" width="${x(146) - x(50)}" height="${yb - T}"/>` +
      `<text x="${x(98)}" y="${T + 12}" text-anchor="middle">DFS, каналы 52–144</text>`;
  }
  let ticks = [];
  if (S.cb === '2.4') for (let c = 1; c <= 14; c++) ticks.push(c);
  else if (S.cb === '5') ticks = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
  else for (let c = 1; c <= 233; c += 16) ticks.push(c);
  const main24 = (c) => S.cb === '2.4' && (c === 1 || c === 6 || c === 11);
  g += ticks.map((c) => `<text x="${x(c)}" y="${H - 10}" text-anchor="middle"${main24(c) ? ' class="lbl" font-weight="700"' : ''}>${c}</text>`).join('');
  g += `<text x="${W - R}" y="${H - 1}" text-anchor="end">канал</text>`;

  const fs = focusSet();
  const list = all.filter((b) => b.band === S.cb).sort((a, b) => a.rssi - b.rssi);
  const shapes = [];
  const grads = new Map();
  const gid = (col) => { if (!grads.has(col)) grads.set(col, 'sg' + grads.size); return grads.get(col); };
  for (const b of list) {
    const hw = b.width / 10 + (S.cb === '2.4' ? 0.2 : 0);
    const x0 = x(b.center - hw), x1 = x(b.center + hw), yt = y(b.rssi);
    const sh = Math.min(x(b.center - hw + 0.5) - x0, (x1 - x0) / 4);
    const col = ssidColor(b.ssid);
    const selected = b.bssid === S.sel, lit = S.hl.has(b.bssid);
    const dim = fs.size && !fs.has(b.ssid);
    g += `<g class="shape" data-bssid="${esc(b.bssid)}" opacity="${dim && !selected ? 0.55 : 1}">` +
      `<title>${esc(b.ssid)} · ${esc(b.bssid)} · канал ${b.channel} · ${b.width} МГц · ${b.rssi} дБм</title>` +
      `<path d="M${x0},${yb} L${x0 + sh},${yt} L${x1 - sh},${yt} L${x1},${yb} Z" fill="url(#${gid(col)})" ` +
      `fill-opacity="${selected || lit ? 1 : 0.5}" stroke="${col}" stroke-width="${selected || lit ? 2.6 : 1.2}" stroke-linejoin="round"/></g>`;
    shapes.push({b, yt, selected, dim});
  }
  let labels = '';
  const placed = [];
  shapes.sort((p, q) => (q.selected - p.selected) || (q.b.rssi - p.b.rssi));
  for (const {b, yt, selected, dim} of shapes) {
    if (!(selected || b.rssi >= -75 || (fs.has(b.ssid) && !dim))) continue;
    const ty = yt < T + 12 ? yt + 13 : yt - 4;
    const w = b.ssid.length * 6.3 + 6, cx = x(b.center);
    const r = {a: cx - w / 2, b: cx + w / 2, c: ty - 11, d: ty + 3};
    if (!selected && placed.some((q) => r.a < q.b && r.b > q.a && r.c < q.d && r.d > q.c)) continue;
    placed.push(r);
    labels += `<text class="lbl" x="${cx}" y="${ty}" text-anchor="middle">${esc(b.ssid)}</text>`;
  }
  const defs = '<defs>' + [...grads].map(([col, id]) =>
    `<linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${col}" stop-opacity=".62"/>` +
    `<stop offset="1" stop-color="${col}" stop-opacity=".05"/></linearGradient>`).join('') + '</defs>';
  return seg + g + defs + labels + '</svg>' + adviceHtml(S.cb);
}

function median(a) {
  if (!a.length) return 0;
  const s = a.slice().sort((p, q) => p - q);
  return s[Math.floor(s.length / 2)];
}

function renderSignal() {
  const modeSeg = `<span class="seg"><button type="button" data-sig="lines" class="${P.sigMode === 'heat' ? '' : 'on'}">Линии</button>` +
    `<button type="button" data-sig="heat" class="${P.sigMode === 'heat' ? 'on' : ''}">Тепловая карта</button></span>`;
  if (P.sigMode === 'heat') return renderHeat(modeSeg);
  const byLevel = P.sigColor !== 'bss';
  const colorSeg = `<span class="seg" title="Как красить линии"><button type="button" data-sigcolor="level" class="${byLevel ? 'on' : ''}">Цвет по уровню</button>` +
    `<button type="button" data-sigcolor="bss" class="${byLevel ? '' : 'on'}">Цвет по BSS</button></span>`;
  const sel = S.data.bss.find((b) => b.bssid === S.sel);
  if (!sel) return `<div class="toolbar">${modeSeg}</div><p class="mut">Выбери строку в таблице: покажу уровень сигнала всех BSS этого SSID.</p>`;
  const group = [sel].concat(S.data.bss.filter((b) => b.ssid === sel.ssid && b.bssid !== sel.bssid)).slice(0, 10);
  const ser = group.map((b, i) => ({b, i, pts: S.data.history[b.bssid] || []}));
  const withPts = ser.filter((s) => s.pts.length >= 2);
  const head = `<div class="toolbar">${modeSeg}${colorSeg}<b>${esc(sel.ssid)}</b>` +
    `<span class="mut">выбранная BSS: мин ${sigSpan(sel.rssi_min)}, среднее ${sigSpan(Math.round(sel.rssi_avg))}, макс ${sigSpan(sel.rssi_max)} дБм; видна в ${sel.seen_pct}% сканов</span>` +
    `<span class="grow"></span><button type="button" class="small" data-hist="1">Скачать историю (CSV)</button></div>`;
  if (!withPts.length) return head + '<p class="mut">Нужно минимум два скана. Включи «Авто», и график начнёт заполняться.</p>';
  const allT = [].concat(...ser.map((s) => s.pts.map((p) => p[0])));
  const tmin = Math.min(...allT), tmax = Math.max(...allT);
  const dts = [];
  for (const s of withPts) for (let i = 1; i < s.pts.length; i++) dts.push(s.pts[i][0] - s.pts[i - 1][0]);
  const gap = Math.max(3 * median(dts), 1);
  const [W, H] = chartSize(132);
  const L = 44, R = 14, T = 12, B = 28;
  const span = Math.max(tmax - tmin, 1);
  const x = (t) => L + (t - tmin) / span * (W - L - R);
  const y = (r) => T + (-30 - clamp(r, -100, -30)) / 70 * (H - T - B);
  let g = svgOpen(W, H) + (byLevel ? sigBackdrop('sgS', y, L, W - R) : '');
  for (let r = -30; r >= -100; r -= 10) {
    g += `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(r)}" y2="${y(r)}"/><text x="${L - 6}" y="${y(r) + 4}" text-anchor="end">${r}</text>`;
  }
  for (let k = 0; k <= 4; k++) {
    const t = tmin + span * k / 4;
    g += `<text x="${x(t)}" y="${H - 8}" text-anchor="${k === 0 ? 'start' : k === 4 ? 'end' : 'middle'}">${k === 4 ? 'сейчас' : '−' + Math.round(tmax - t) + ' с'}</text>`;
  }
  for (const s of ser.slice().reverse()) {
    if (!s.pts.length) continue;
    const isSel = s.b.bssid === S.sel;
    const col = byLevel ? 'url(#sgS)' : seriesColor(s.i);
    let d = '', prev = null;
    for (const [t, r] of s.pts) {
      d += (prev === null || t - prev > gap ? 'M' : 'L') + x(t).toFixed(1) + ',' + y(r).toFixed(1) + ' ';
      prev = t;
    }
    const dash = byLevel && DASHES[s.i % DASHES.length] ? ` stroke-dasharray="${DASHES[s.i % DASHES.length]}"` : '';
    g += `<path d="${d}" fill="none" stroke="${col}" stroke-width="${isSel ? 3 : 1.6}"${dash} opacity="${isSel ? 1 : 0.85}"/>`;
    if (s.pts.length <= 60) g += s.pts.map(([t, r]) => `<circle cx="${x(t).toFixed(1)}" cy="${y(r).toFixed(1)}" r="${isSel ? 3 : 2}" style="fill:${byLevel ? sigFill(r) : seriesColor(s.i)}"><title>${esc(s.b.bssid)}: ${r} дБм, ${Math.round(tmax - t)} с назад</title></circle>`).join('');
  }
  g += '</svg>';
  const mark = (s) => byLevel
    ? `<svg class="dash" width="26" height="8" aria-hidden="true"><line x1="1" x2="25" y1="4" y2="4"${DASHES[s.i % DASHES.length] ? ` stroke-dasharray="${DASHES[s.i % DASHES.length]}"` : ''} stroke-width="${s.b.bssid === S.sel ? 3 : 2}"/></svg>`
    : `<span class="dot" style="background:${seriesColor(s.i)}"></span>`;
  const legend = '<div class="legend">' + ser.map((s) =>
    `<span data-bssid="${esc(s.b.bssid)}">${mark(s)}` +
    `<span class="mono">${esc(s.b.bssid)}</span>&nbsp;${esc(s.b.band)} ГГц, канал ${s.b.channel},&nbsp;${sigSpan(s.b.rssi, ' дБм')}</span>`).join('') +
    (byLevel ? sigScaleLegend() : '') + '</div>';
  return head + g + legend;
}

// ---------- обзор: распределения одним экраном ----------
function countBy(list, fn) {
  const m = new Map();
  for (const b of list) { const k = fn(b); m.set(k, (m.get(k) || 0) + 1); }
  return [...m.entries()].map(([label, n]) => ({label, n})).sort((a, b) => b.n - a.n);
}

function hbars(title, rows) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  const body = rows.length ? rows.map((r) =>
    `<div class="hb" title="${esc(r.label)}: ${r.n}"><span class="hlab">${esc(r.label)}</span>` +
    `<span class="htrack"><i style="width:${(r.n / max * 100).toFixed(1)}%${r.color ? ';background:' + r.color : ''}"></i></span><span class="hval">${r.n}</span></div>`).join('')
    : '<div class="mut">нет данных</div>';
  return `<div class="ov"><div class="sub">${esc(title)}</div>${body}</div>`;
}

function vbars(title, band, chans, wide) {
  const fs = focusSet();
  const list = S.data.bss.filter((b) => b.band === band);
  if (!list.length) return '';
  const all = [...new Set(chans.concat(list.map((b) => b.channel)))].sort((a, b) => a - b);
  const data = all.map((c) => {
    const on = list.filter((b) => b.channel === c);
    const mine = fs.size ? on.filter((b) => fs.has(b.ssid)).length : on.length;
    const utils = on.filter((b) => b.util != null).map((b) => b.util);
    return {c, mine, other: on.length - mine, total: on.length, util: utils.length ? Math.max(...utils) : null};
  });
  const max = Math.max(1, ...data.map((d) => d.total));
  const cols = data.map((d) => {
    const tip = `канал ${d.c}: BSS ${d.total}` + (fs.size ? `, из них мои ${d.mine}` : '') + (d.util == null ? '' : `, макс. загрузка ${d.util.toFixed(0)}%`);
    return `<div class="vc" title="${esc(tip)}"><span class="vnum">${d.total || ''}</span><span class="vplot">` +
      `<span class="vstack" style="height:${(d.total / max * 100).toFixed(1)}%">` +
      `${d.other ? `<i class="o" style="flex:${d.other}"></i>` : ''}${d.mine ? `<i class="m" style="flex:${d.mine}"></i>` : ''}</span></span>` +
      `<span class="vlab">${d.c}</span></div>`;
  }).join('');
  const legend = fs.size ? '<div class="vleg"><span><i class="m"></i>мои SSID</span><span><i class="o"></i>остальные</span></div>' : '';
  return `<div class="ov${wide ? ' wide' : ''}"><div class="sub">${esc(title)}</div><div class="vb">${cols}</div>${legend}</div>`;
}

function bssOverTime() {
  const m = new Map();
  for (const pts of Object.values(S.data.history)) for (const p of pts) m.set(p[0], (m.get(p[0]) || 0) + 1);
  const ser = [...m.entries()].sort((a, b) => a[0] - b[0]).slice(-120);
  if (ser.length < 2) return `<div class="ov"><div class="sub">Число BSS по сканам</div><div class="mut">Нужно минимум два скана.</div></div>`;
  const vs = ser.map((p) => p[1]);
  const lo = Math.min(...vs), hi = Math.max(...vs);
  const W = 300, H = 64, a = 0, z = hi * 1.15 + 1;   // шкала от нуля: иначе разница в одну BSS выглядит как обвал
  const x = (i) => 2 + i / (ser.length - 1) * (W - 4), y = (v) => 3 + (z - v) / (z - a) * (H - 6);
  const d = ser.map((p, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(p[1]).toFixed(1)).join(' ');
  return `<div class="ov"><div class="sub">Число BSS по сканам</div>` +
    `<svg class="mini" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Число BSS по сканам">` +
    `<title>за ${ser.length} сканов: от ${lo} до ${hi} BSS</title><path d="${d}"/></svg>` +
    `<div class="mut">сейчас ${vs[vs.length - 1]}, минимум ${lo}, максимум ${hi} за ${ser.length} сканов</div></div>`;
}

function renderOverview() {
  const all = S.data.bss;
  const sig = [['от −50 (отличный)', -50, 0, -45], ['−50…−60 (хороший)', -60, -50, -55], ['−60…−67 (рабочий)', -67, -60, -64],
    ['−67…−75 (слабый)', -75, -67, -71], ['−75…−85 (плохой)', -85, -75, -80], ['ниже −85 (на грани)', -200, -85, -90]]
    .map(([label, lo, hi, mid]) => ({label, color: sigFill(mid), n: all.filter((b) => b.rssi >= lo && (hi === 0 || b.rssi < hi)).length}));
  const gens = countBy(all, (b) => b.gen === 'legacy' ? 'legacy (a/b/g)' : b.gen).sort((a, b) => b.label.localeCompare(a.label));
  const widths = countBy(all, (b) => b.width + ' МГц').sort((a, b) => parseInt(a.label, 10) - parseInt(b.label, 10));
  let vend = countBy(all, (b) => b.vendor || (b.random_mac ? 'локальный MAC' : 'неизвестен'));
  if (vend.length > 6) vend = vend.slice(0, 5).concat({label: 'остальные', n: vend.slice(5).reduce((s, r) => s + r.n, 0)});
  const ch5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
  return '<div class="ovgrid">' +
    vbars('BSS по каналам, 2.4 ГГц', '2.4', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]) +
    vbars('BSS по каналам, 5 ГГц', '5', ch5, true) +
    vbars('BSS по каналам, 6 ГГц', '6', [], true) +
    hbars('Уровень сигнала, дБм', sig) +
    hbars('Защита', countBy(all, (b) => b.security).slice(0, 7)) +
    hbars('Поколение Wi-Fi', gens) +
    hbars('Ширина канала', widths) +
    hbars('Вендоры', vend) +
    bssOverTime() +
    '</div>';
}

// ---------- тепловая карта сигнала ----------
function renderHeat(modeSeg) {
  const sel = S.data.bss.find((b) => b.bssid === S.sel);
  let rows = (P.heatAll || !sel) ? S.data.bss.slice() : S.data.bss.filter((b) => b.ssid === sel.ssid);
  rows.sort((a, b) => b.rssi - a.rssi);
  const total = rows.length;
  rows = rows.slice(0, 24);
  const head = `<div class="toolbar">${modeSeg}<label class="chk"><input type="checkbox" data-heatall="1"${P.heatAll ? ' checked' : ''}> все BSS</label>` +
    `<span class="mut">${P.heatAll || !sel ? 'самые сильные BSS' : 'BSS сети ' + esc(sel.ssid)}${total > rows.length ? `, показаны ${rows.length} из ${total}` : ''}</span>` +
    `<span class="grow"></span><button type="button" class="small" data-hist="1">Скачать историю (CSV)</button></div>`;
  const times = [...new Set([].concat(...rows.map((b) => (S.data.history[b.bssid] || []).map((p) => p[0]))))].sort((a, b) => a - b).slice(-90);
  if (times.length < 2) return head + '<p class="mut">Нужно минимум два скана. Включи «Авто», и карта начнёт заполняться.</p>';
  const [W] = chartSize(0);
  const L = 250, R = 54, T = 4, ch = 18;
  const cw = clamp((W - L - R) / times.length, 4, 30);
  const H = T + rows.length * ch + 20;
  const tmax = times[times.length - 1];
  let g = svgOpen(W, H);
  rows.forEach((b, i) => {
    const yy = T + i * ch, isSel = b.bssid === S.sel;
    const m = new Map((S.data.history[b.bssid] || []).map((p) => [p[0], p[1]]));
    const name = b.ssid.length > 18 ? b.ssid.slice(0, 17) + '…' : b.ssid;
    g += `<g class="shape" data-bssid="${esc(b.bssid)}"><title>${esc(b.ssid)} · ${esc(b.bssid)}</title>` +
      `<text x="${L - 8}" y="${yy + 13}" text-anchor="end"${isSel ? ' class="lbl" font-weight="700"' : ''}>${esc(name)} ${esc(b.bssid.slice(-5))}, ${esc(b.band)} ГГц</text></g>`;
    times.forEach((t, j) => {
      const r = m.get(t);
      if (r === undefined) return;
      g += `<rect class="hc" x="${(L + j * cw).toFixed(1)}" y="${yy}" width="${Math.max(cw - 1, 2).toFixed(1)}" height="${ch - 2}" style="fill:${sigFill(r)}">` +
        `<title>${esc(b.ssid)}: ${r} дБм, ${Math.round(tmax - t)} с назад</title></rect>`;
    });
    if (isSel) g += `<rect class="hsel" x="${L - 2}" y="${yy - 1}" width="${(times.length * cw + 3).toFixed(1)}" height="${ch}"/>`;
    g += `<text x="${(L + times.length * cw + 6).toFixed(1)}" y="${yy + 13}" style="fill:${sigText(b.rssi)};font-weight:${isSel ? 700 : 600}">${b.rssi}</text>`;
  });
  const yb = T + rows.length * ch + 13;
  g += `<text x="${L}" y="${yb}">−${Math.round(tmax - times[0])} с</text><text x="${(L + times.length * cw).toFixed(1)}" y="${yb}" text-anchor="end">сейчас</text></svg>`;
  const legend = '<div class="hleg"><span class="mut">слабее</span>' +
    [-90, -85, -80, -75, -70, -67, -63, -60, -55, -50, -40].map((r) => `<span><i style="background:${sigFill(r)}"></i>${r}</span>`).join('') +
    '<span class="mut">сильнее, дБм. Пустая клетка: в этом скане BSS не слышна.</span></div>';
  return head + g + legend;
}

// ---------- утилизация каналов (QBSS Load) ----------
// Цвет от зелёного (свободно) к красному (перегружен). Цвет дублируется подписью уровня и числом.
function utilColor(u) {
  // к 75% оттенок доходит до чистого красного: всё, что выше, уже «перегружен», а не «чуть оранжевее»
  const hue = Math.round(130 * (1 - clamp(u / 75, 0, 1)));
  return `hsl(${hue} ${DARK ? '65% 52%' : '70% 38%'})`;
}

function utilSpark(series) {
  if (!series || series.length < 2) return '<span class="mut">—</span>';
  const W = 96, H = 22;
  const x = (i) => 1 + i / (series.length - 1) * (W - 4), y = (v) => 2 + (100 - v) / 100 * (H - 4);   // шкала всегда 0–100%
  const d = series.map((p, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(p[1]).toFixed(1)).join(' ');
  const last = series[series.length - 1][1];
  const vs = series.map((p) => p[1]);
  return `<svg class="spark" width="${W}" height="${H}" role="img" aria-label="загрузка по сканам">` +
    `<title>за ${series.length} сканов: от ${Math.min(...vs).toFixed(0)} до ${Math.max(...vs).toFixed(0)}%</title>` +
    `<line x1="0" x2="${W}" y1="${y(50)}" y2="${y(50)}" class="ug"/><path d="${d}" style="stroke:${utilColor(last)}"/></svg>`;
}

function renderUtil() {
  const U = S.data.util || {channels: [], no_data: []};
  const fs = focusSet();
  const lead = '<p class="mut ulead">Источник — QBSS Load (IE 11) в beacon: доля времени, когда сама AP считает канал занятым. ' +
    'На канал берётся максимум среди AP, которые сообщают эту цифру. Нажми на строку, чтобы выбрать самую загруженную AP канала.</p>';
  const stops = [0, 15, 30, 50, 70, 75, 100].map((u) => `${utilColor(u)} ${u}%`).join(', ');
  const legend = `<div class="uleg"><span class="ugw"><span class="ugrad" style="background:linear-gradient(90deg, ${stops})"></span>` +
    '<span class="uticks"><span style="left:0">0%</span><span style="left:30%">30</span><span style="left:50%">50</span><span style="left:70%">70</span><span style="left:100%">100%</span></span></span>' +
    '<span class="mut">до 30% свободен, 30–50% умеренная, 50–70% высокая, от 70% перегружен</span></div>';
  if (!U.channels.length) {
    return lead + '<p>Ни одна AP в эфире не вещает QBSS Load, поэтому загрузку каналов по beacon узнать нельзя.' +
      (U.no_data.length ? ` Каналов без данных: ${U.no_data.length}.` : '') + '</p>';
  }
  let html = lead + legend;
  for (const band of ['2.4', '5', '6']) {
    const rows = U.channels.filter((c) => c.band === band);
    if (!rows.length) continue;
    html += `<div class="sub">${band} ГГц</div>`;
    html += rows.map((c) => {
      const col = utilColor(c.max);
      const mine = c.aps.some((a) => fs.has(a.ssid));
      const top = c.aps.slice(0, 3).map((a) => `${esc(a.ssid)} ${a.util.toFixed(0)}%`).join(', ') + (c.aps.length > 3 ? ` и ещё ${c.aps.length - 3}` : '');
      const tip = `канал ${c.channel}: максимум ${c.max.toFixed(0)}%, среднее ${c.avg.toFixed(0)}% по ${c.reporting} AP`;
      return `<div class="urow" data-bssid="${esc(c.aps[0].bssid)}" title="${esc(tip)}" tabindex="0">` +
        `<span class="uch">${c.channel}</span>` +
        `<span class="utrack"><i style="width:${Math.max(c.max, 1).toFixed(1)}%;background:${col}"></i><b style="left:30%"></b><b style="left:50%"></b><b style="left:70%"></b></span>` +
        `<span class="uval">${c.max.toFixed(0)}%</span>` +
        `<span class="ulvl"><i style="background:${col}"></i>${esc(c.label)}${mine ? '<span class="tag">мои</span>' : ''}</span>` +
        `<span class="uspark">${utilSpark(c.series)}</span>` +
        `<span class="uaps mut">AP ${c.reporting} из ${c.bss}, станций ${c.stations}: ${top}</span></div>`;
    }).join('');
  }
  if (U.no_data.length) {
    html += `<p class="mut">Нет данных QBSS Load (AP не вещают загрузку): ` +
      U.no_data.map((c) => `${c.band} ГГц канал ${c.channel} (BSS ${c.bss})`).join(', ') + '.</p>';
  }
  return html;
}

function renderExportMenu() {
  const fs = focusSet();
  const total = S.data ? S.data.bss.length : 0;
  $('ecTable').textContent = `(${visibleBss().length})`;
  $('ecAll').textContent = `(${total})`;
  $('ecFocus').textContent = fs.size ? `(${S.data.bss.filter((b) => fs.has(b.ssid)).length})` : '(не заданы)';
  const focusRadio = document.querySelector('input[name=expScope][value=focus]');
  focusRadio.disabled = !fs.size;
  $('ecFocusWrap').classList.toggle('mut', !fs.size);
  let sc = P.expScope || 'table';
  if (sc === 'focus' && !fs.size) sc = 'table';
  for (const r of document.querySelectorAll('input[name=expScope]')) r.checked = r.value === sc;
}

// ---------- журнал подключения ноутбука ----------
const STATE_RU = {connected: 'подключён', disconnected: 'отключён', disconnecting: 'отключается', associating: 'ассоциация',
  authenticating: 'аутентификация', discovering: 'поиск сети', not_ready: 'адаптер не готов', ad_hoc: 'ad hoc', unknown: 'неизвестно'};
const KIND_RU = {connected: 'подключение', disconnected: 'обрыв', roam: 'роуминг', ssid_change: 'смена сети',
  pingpong: 'пинг-понг', sticky: 'залипание', attempt_fail: 'неудачное подключение', disconnect_reason: 'отключение (Windows)'};

function fmtClock(t) { return new Date(t * 1000).toLocaleTimeString('ru-RU'); }
function fmtDur(s) {
  if (s == null) return '';
  if (s < 90) return Math.round(s) + ' с';
  if (s < 5400) return Math.round(s / 60) + ' мин';
  return (s / 3600).toFixed(1) + ' ч';
}
function bssLabel(bssid) {
  const b = S.data.bss.find((x) => x.bssid === bssid);
  return b ? `${b.band} ГГц, кан. ${b.channel}` : '';
}

function connChart(C, win) {
  const now = S.data.now;
  const t0 = now - win;
  const samples = (C.samples || []).filter((s) => s[0] >= t0);
  if (samples.length < 2) return '<p class="mut">Замеров пока мало: журнал пишется раз в секунду.</p>';
  const [W, H] = chartSize(260);
  const L = 44, R = 14, T = 16, B = 24;
  const x = (t) => L + (t - t0) / win * (W - L - R);
  const y = (r) => T + (-30 - clamp(r, -100, -30)) / 70 * (H - T - B);
  const order = [];
  for (const s of samples) if (s[2] && !order.includes(s[2])) order.push(s[2]);
  const col = (b) => laneColor(order.indexOf(b));
  const laneY = H - B - 7;          // полоса снизу: к какой BSS был подключён ноутбук
  let g = svgOpen(W, H) + sigBackdrop('sgC', y, L, W - R);
  for (let r = -30; r >= -100; r -= 10) {
    g += `<line class="grid" x1="${L}" x2="${W - R}" y1="${y(r)}" y2="${y(r)}"/><text x="${L - 6}" y="${y(r) + 4}" text-anchor="end">${r}</text>`;
  }
  for (const r of [-67, -75]) g += `<line class="ref" x1="${L}" x2="${W - R}" y1="${y(r)}" y2="${y(r)}"><title>${r} дБм</title></line>`;
  // периоды без связи - красные полосы
  let downFrom = null;
  const bands = [];
  for (const s of samples) {
    if (s[1] === null && downFrom === null) downFrom = s[0];
    if (s[1] !== null && downFrom !== null) { bands.push([downFrom, s[0]]); downFrom = null; }
  }
  if (downFrom !== null) bands.push([downFrom, samples[samples.length - 1][0]]);
  for (const [a, b] of bands) {
    g += `<rect class="down" x="${x(a).toFixed(1)}" y="${T}" width="${Math.max(2, x(b) - x(a)).toFixed(1)}" height="${H - T - B}">` +
      `<title>без связи ${fmtDur(b - a)} (${fmtClock(a)}–${fmtClock(b)})</title></rect>`;
  }
  // линия RSSI окрашена по уровню; отдельный отрезок на каждую BSS, BSS видна по полосе снизу
  let d = '', cur = null, prev = null, segFrom = null;
  const lanes = [];
  const flush = (tEnd) => {
    if (d && cur) g += `<path d="${d}" fill="none" stroke="url(#sgC)" stroke-width="2.4" stroke-linejoin="round"><title>${esc(cur)}</title></path>`;
    if (cur && segFrom !== null) lanes.push([cur, segFrom, tEnd]);
    d = ''; segFrom = null;
  };
  for (const s of samples) {
    if (s[1] === null) { flush(prev); cur = null; prev = null; continue; }
    if (s[2] !== cur || (prev !== null && s[0] - prev > 5)) { flush(prev); cur = s[2]; d = 'M'; segFrom = s[0]; } else d += ' L';
    d += x(s[0]).toFixed(1) + ',' + y(s[1]).toFixed(1);
    prev = s[0];
  }
  flush(prev);
  for (const [b, a, z] of lanes) {
    g += `<rect x="${x(a).toFixed(1)}" y="${laneY}" width="${Math.max(2, x(z) - x(a)).toFixed(1)}" height="5" rx="1" style="fill:${col(b)}">` +
      `<title>${esc(b)} ${esc(bssLabel(b))}: ${fmtClock(a)}–${fmtClock(z)}</title></rect>`;
  }
  // события: роуминг - пунктир, проблемы - метки сверху
  let lastLbl = -1e9;
  for (const e of (C.events || []).filter((ev) => ev.t >= t0)) {
    const xx = x(e.t).toFixed(1);
    if (e.kind === 'roam') {
      g += `<line class="roam" x1="${xx}" x2="${xx}" y1="${T}" y2="${H - B}"><title>${fmtClock(e.t)} роуминг ${esc(e.bssid_from)} → ${esc(e.bssid_to)}</title></line>`;
      if (xx - lastLbl > 70) { g += `<text x="${+xx + 3}" y="${T + 10}">роуминг</text>`; lastLbl = +xx; }
    } else if (e.severity !== 'info') {
      g += `<g class="evm ${e.severity}"><circle cx="${xx}" cy="${T + 4}" r="4.5"/><title>${fmtClock(e.t)} ${esc(KIND_RU[e.kind] || e.kind)}: ${esc(e.text)}${e.reason ? '. ' + esc(e.reason) : ''}</title></g>`;
    }
  }
  for (let k = 0; k <= 4; k++) {
    const t = t0 + win * k / 4;
    g += `<text x="${x(t)}" y="${H - 6}" text-anchor="${k === 0 ? 'start' : k === 4 ? 'end' : 'middle'}">${k === 4 ? 'сейчас' : fmtClock(t)}</text>`;
  }
  g += '</svg>';
  const legend = '<div class="legend"><span class="mut">полоса снизу - BSS:</span>' + order.map((b) => `<span data-bssid="${esc(b)}"><span class="lane" style="background:${col(b)}"></span>` +
    `<span class="mono">${esc(b)}</span>&nbsp;${esc(bssLabel(b))}</span>`).join('') +
    '<span><span class="swatch down"></span>без связи</span><span><span class="swatch roam"></span>роуминг</span>' + sigScaleLegend() + '</div>';
  return g + legend;
}

// MCS подключения Windows не отдаёт; подбираем MCS/потоки/ширину/GI, которые дают ровно такую скорость
function mcsGuess(dir, list) {
  if (!list) return `<span class="mut">${dir}: нет данных</span>`;
  if (!list.length) return `<span class="mut">${dir}: скорость не совпала ни с одним MCS</span>`;
  const c = list[0];
  const main = c.phy === 'legacy' ? `legacy ${c.rate} Мбит/с` : `${c.phy} MCS ${c.mcs} <span class="mut">(${esc(c.mod)})</span>, ${c.nss}×, ${c.width} МГц, GI ${c.gi}`;
  const alt = list.length > 1 ? `<span class="mut" title="${esc(list.slice(1).map((x) => x.text).join('\n'))}"> или ещё ${list.length - 1} вар.</span>` : '';
  return `<span class="mut">${dir}:</span> ${main}${alt}`;
}

function renderConn() {
  const C = S.data.conn || {};
  const cur = C.current;
  const st = C.stats || {};
  const win = P.connWin || 900;
  const up = cur && cur.state === 'connected' && cur.bssid;
  const kv = (k, v, cls) => `<div${cls ? ` class="${cls}"` : ''}><span class="mut">${esc(k)}</span><b>${v}</b></div>`;
  let card;
  if (!cur) card = `<p class="mut">Журнал ещё не получил ни одного замера. ${esc(C.status || '')}</p>`;
  else {
    card = '<div class="ccard">' +
      kv('Состояние', `<span class="cst ${up ? 'good' : 'bad'}">●</span> ${esc(STATE_RU[cur.state] || cur.state)}`) +
      (up ? kv('Сеть', esc(cur.ssid) + (cur.profile && cur.profile !== cur.ssid ? ` <span class="mut">(профиль ${esc(cur.profile)})</span>` : '')) +
        kv('BSSID', `<span class="mono">${esc(cur.bssid)}</span>${cur.vendor ? ' <span class="mut">' + esc(cur.vendor) + '</span>' : ''}`) +
        kv('Канал', cur.channel != null ? `${cur.channel}${bssLabel(cur.bssid) ? ' <span class="mut">(' + esc(bssLabel(cur.bssid)) + ')</span>' : ''}` : '—') +
        kv('Сигнал', `${sigSpan(cur.rssi, ' дБм')}, качество ${cur.quality}%`) +
        kv('Скорость', `приём ${cur.rx_mbps} / передача ${cur.tx_mbps} Мбит/с`) +
        kv('MCS по скорости (оценка)', mcsGuess('приём', cur.rx_mcs) + '<br>' + mcsGuess('передача', cur.tx_mcs), 'wide') +
        kv('Защита', `${esc(cur.auth)}, ${esc(cur.cipher)}${cur.onex ? ', 802.1X' : ''}`) : '') +
      '</div>';
  }
  const stat = (label, n, cls) => `<span class="it"><span class="mut">${label}</span><b class="${n ? cls : ''}">${n}</b></span>`;
  const stats = '<div class="cstats">' + stat('роумингов', st.roams || 0, '') +
    stat('обрывов', st.disconnects || 0, 'bad') + (st.down_s ? `<span class="it mut">без связи ${fmtDur(st.down_s)}</span>` : '') +
    stat('пинг-понгов', st.pingpong || 0, 'mid') + stat('залипаний', st.sticky || 0, 'mid') +
    stat('неудачных подключений', st.attempt_fail || 0, 'bad') +
    (st.since ? `<span class="it mut">журнал с ${fmtClock(st.since)}</span>` : '') + '</div>';
  const tools = `<div class="toolbar"><span class="seg">${[[300, '5 мин'], [900, '15 мин'], [1800, '30 мин']].map(([v, l]) =>
    `<button type="button" data-cwin="${v}" class="${win === v ? 'on' : ''}">${l}</button>`).join('')}</span>` +
    `<span class="seg">${[['all', 'все события'], ['bad', 'только проблемы']].map(([v, l]) =>
      `<button type="button" data-cfilter="${v}" class="${(S.cfilter || 'all') === v ? 'on' : ''}">${l}</button>`).join('')}</span>` +
    `<span class="grow"></span><span class="mut small">${esc(C.status || '')}</span>` +
    `<button type="button" class="small" data-journal="csv">Скачать журнал (CSV)</button>` +
    `<button type="button" class="small" data-journal="clear">Очистить</button></div>`;
  let evs = (C.events || []).slice().reverse();
  if (S.cfilter === 'bad') evs = evs.filter((e) => e.severity !== 'info');
  const rows = evs.slice(0, 200).map((e) => {
    const rs = [e.rssi_from, e.rssi_to].filter((v) => v != null).map((v) => sigSpan(v)).join(' → ');
    const mv = e.bssid_from || e.bssid_to ? `<span class="mono">${esc(e.bssid_from)}${e.bssid_from && e.bssid_to ? ' → ' : ''}${esc(e.bssid_to)}</span>` : '';
    return `<tr class="ev ${e.severity}"><td class="num">${fmtClock(e.t)}</td><td><span class="evk ${e.severity}">${esc(KIND_RU[e.kind] || e.kind)}</span></td>` +
      `<td>${esc(e.text)}${e.reason ? `<div class="mut">Причина: ${esc(e.reason)}${e.reason_code != null ? ' (0x' + e.reason_code.toString(16).toUpperCase() + ')' : ''}</div>` : ''}</td>` +
      `<td>${mv}</td><td class="num">${rs ? rs + ' дБм' : ''}</td><td class="num">${e.duration_s != null ? fmtDur(e.duration_s) : ''}</td></tr>`;
  }).join('');
  const table = rows ? `<table class="mini evt"><thead><tr><th>Время</th><th>Событие</th><th>Что произошло</th><th>BSSID</th><th>RSSI</th><th>Длит.</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<p class="mut">Событий пока нет.</p>';
  const dwell = (st.dwell || []).slice(0, 8);
  const maxd = Math.max(1, ...dwell.map((d) => d.s));
  const dw = dwell.length ? '<div class="sub">Время на каждой BSS</div>' + dwell.map((d) =>
    `<div class="hb" data-bssid="${esc(d.bssid)}"><span class="hlab mono">${esc(d.bssid)} <span class="mut">${esc(bssLabel(d.bssid))}</span></span>` +
    `<span class="htrack"><i style="width:${(d.s / maxd * 100).toFixed(1)}%"></i></span><span class="hval">${fmtDur(d.s)}</span></div>`).join('') : '';
  const raw = (C.raw || []).length ? `<details class="raw"><summary class="mut">Сырые уведомления Windows (${C.raw.length}) — для отладки</summary>` +
    `<div class="mono small">${C.raw.slice().reverse().map((r) => `${fmtClock(r.t)} src=${r.source} code=${r.code} ${esc(r.name)}`).join('<br>')}</div></details>` : '';
  return card + stats + tools + connChart(C, win) + `<div class="cgrid"><div>${table}</div><div>${dw}${raw}</div></div>`;
}

// ---------- обход: план этажа и карта покрытия ----------
const SV_BINS = [[-60, 130, 'от −60: отлично'], [-67, 95, '−60…−67: голос и видео'], [-72, 55, '−67…−72: данные'],
  [-80, 25, '−72…−80: слабо'], [-200, 0, 'ниже −80: нет покрытия']];
const CNT_BINS = [[3, 130, '3 и больше'], [2, 95, '2: роуминг возможен'], [1, 35, '1: нет запасной AP'], [0, 0, '0: не слышно']];

function svColor(v, alpha) {
  const bins = S.svLayer && S.svLayer.startsWith('cnt:') ? CNT_BINS : SV_BINS;
  const hue = (bins.find(([lo]) => v >= lo) || bins[bins.length - 1])[1];
  return `hsla(${hue}, 72%, ${DARK ? 52 : 44}%, ${alpha})`;
}

function svRgb(v) {
  // тот же цвет, что svColor, но числами для ImageData
  const bins = S.svLayer && S.svLayer.startsWith('cnt:') ? CNT_BINS : SV_BINS;
  const hh = (bins.find(([lo]) => v >= lo) || bins[bins.length - 1])[1] / 360, ss = 0.72, ll = (DARK ? 52 : 44) / 100;
  const q = ll < 0.5 ? ll * (1 + ss) : ll + ss - ll * ss, pp = 2 * ll - q;
  const f = (t) => { t = (t + 1) % 1; return t < 1 / 6 ? pp + (q - pp) * 6 * t : t < 0.5 ? q : t < 2 / 3 ? pp + (q - pp) * (2 / 3 - t) * 6 : pp; };
  return [Math.round(f(hh + 1 / 3) * 255), Math.round(f(hh) * 255), Math.round(f(hh - 1 / 3) * 255)];
}

function svLayers() {
  const pts = (S.survey && S.survey.points) || [];
  const cnt = new Map();
  for (const p of pts) for (const v of Object.values(p.results || {})) cnt.set(v[0], (cnt.get(v[0]) || 0) + 1);
  const fs = S.data ? S.data.focus : [];
  const ssids = [...new Set(fs.concat([...cnt.entries()].sort((a, b) => b[1] - a[1]).map((e) => e[0])))].filter((s) => s && s !== '<hidden>').slice(0, 30);
  const out = ssids.map((s) => ['ssid:' + s, 'Сигнал сети ' + s]);
  out.push(['conn', 'Сигнал подключения ноутбука']);
  for (const s of ssids.slice(0, 5)) out.push(['cnt:' + s, 'Сколько BSS сети ' + s + ' слышно от −75']);
  return out;
}

function svValue(p, layer) {
  if (p.status !== 'done') return null;
  const res = Object.values(p.results || {});
  if (layer === 'conn') return p.conn && p.conn.rssi != null ? p.conn.rssi : null;
  if (layer.startsWith('ssid:')) {
    const n = layer.slice(5);
    const v = res.filter((r) => r[0] === n).map((r) => r[3]);
    return v.length ? Math.max(...v) : -100;          // сеть не слышна в точке - это «нет покрытия», а не пропуск
  }
  if (layer.startsWith('cnt:')) { const n = layer.slice(4); return res.filter((r) => r[0] === n && r[3] >= -75).length; }
  return null;
}

function svFmt(v) {
  if (v == null) return '—';
  return S.svLayer && S.svLayer.startsWith('cnt:') ? String(v) : v <= -100 ? 'нет' : v + '';
}

function renderSurveyShell() {
  const sv = S.data.survey || {};
  if (!sv.has_plan) {
    return '<div class="svempty"><p><b>Обход с картой покрытия.</b> Загрузи план этажа, встань в точку и нажми на её место на плане: ' +
      'программа сделает скан и запомнит, что слышно в этой точке. По точкам строится карта покрытия выбранной сети.</p>' +
      '<div class="toolbar"><button type="button" class="primary" data-sv="plan">Загрузить план этажа (PNG или JPG)</button>' +
      '<button type="button" data-sv="open">Открыть проект обхода</button></div>' +
      '<p class="mut">Совет: точки ставь через 5–10 м и обязательно у границ помещений. Ноутбук держи так, как его держат пользователи.</p></div>';
  }
  const layers = svLayers();
  if (!S.svLayer || !layers.some(([k]) => k === S.svLayer)) S.svLayer = layers[0] ? layers[0][0] : 'conn';
  const bins = S.svLayer.startsWith('cnt:') ? CNT_BINS : SV_BINS;
  return `<div class="toolbar"><span class="seg"><button type="button" data-svmode="measure" class="${S.svMode !== 'view' ? 'on' : ''}">Замер</button>` +
    `<button type="button" data-svmode="view" class="${S.svMode === 'view' ? 'on' : ''}">Просмотр</button></span>` +
    `<select id="svLayer" aria-label="Что показывать на карте">${layers.map(([k, l]) => `<option value="${esc(k)}"${k === S.svLayer ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>` +
    `<label class="chk">прозрачность <input type="range" id="svOpacity" min="0.15" max="0.85" step="0.05" value="${P.svOpacity || 0.5}"></label>` +
    `<label class="chk"><input type="checkbox" id="svVals"${S.svVals === false ? '' : ' checked'}> значения</label>` +
    `<span class="grow"></span><span class="mut" id="svInfo"></span>` +
    `<button type="button" class="small" data-sv="save">Сохранить проект</button><button type="button" class="small" data-sv="open">Открыть</button>` +
    `<button type="button" class="small" data-sv="png">Карта в PNG</button><button type="button" class="small" data-sv="plan">Новый план</button>` +
    `<button type="button" class="small" data-sv="clear">Удалить все точки</button>` +
    `<button type="button" class="small" data-sv="max">${$('app').classList.contains('max') ? 'Обычный вид' : 'Во весь экран'}</button></div>` +
    `<div class="svleg">${bins.map(([lo, h, l]) => `<span><i style="background:hsla(${h},72%,${DARK ? 52 : 44}%,.85)"></i>${esc(l)}</span>`).join('')}` +
    `<span class="mut">${S.svMode === 'view' ? 'Нажми на точку, чтобы увидеть подробности.' : 'Встань в точку и нажми на её место на плане: скан займёт около 5 секунд.'}</span></div>` +
    `<div class="svmain"><div class="svwrap" id="svWrap"><img id="svImg" alt="План этажа" draggable="false">` +
    `<canvas id="svHeat"></canvas><svg id="svPts"></svg></div><div class="svside" id="svSide"></div></div>`;
}

function svPlanUrl() {
  const sv = S.data.survey;
  if (S.svPlanRev === sv.plan_rev && S.svPlanUrl) return Promise.resolve(S.svPlanUrl);
  return api('/api/survey/plan', undefined, true).then(async (r) => {
    if (!r.ok) throw new Error('план не загрузился');
    if (S.svPlanUrl) URL.revokeObjectURL(S.svPlanUrl);
    S.svPlanUrl = URL.createObjectURL(await r.blob());
    S.svPlanRev = sv.plan_rev;
    return S.svPlanUrl;
  });
}

async function svFetchPoints() {
  const sv = S.data.survey || {};
  if (S.survey && S.survey.rev === sv.rev) return false;
  const r = await api('/api/survey/points');
  if (r.ok) { S.survey = r.data; return true; }
  return false;
}

function svFit() {
  // план целиком в панели: иначе часть плана уходит за край окна и по ней нельзя кликнуть
  const img = $('svImg'), wrap = $('svWrap'), pb = $('panelBody');
  if (!img || !wrap) return;
  const top = wrap.getBoundingClientRect().top - pb.getBoundingClientRect().top + pb.scrollTop;
  img.style.maxHeight = Math.max(200, pb.clientHeight - top - 14) + 'px';
}

function svDraw() {
  const img = $('svImg'), cv = $('svHeat'), svg = $('svPts');
  if (!img || !img.naturalWidth) return;
  svFit();
  const w = img.clientWidth, h = img.clientHeight, dpr = window.devicePixelRatio || 1;
  cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
  cv.style.width = w + 'px'; cv.style.height = h + 'px';
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`); svg.style.width = w + 'px'; svg.style.height = h + 'px';
  const pts = ((S.survey && S.survey.points) || []).map((p) => ({p, v: svValue(p, S.svLayer), px: p.x * w, py: p.y * h}));
  const valued = pts.filter((q) => q.v != null);
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const alpha = +(P.svOpacity || 0.5);
  if (valued.length) {
    // IDW (вес 1/d²) в радиусе от ближайшей точки: вдали от замеров карта не выдумывает покрытие.
    // Радиус - от типичного расстояния между соседними точками, край мягкий; считаем в низком разрешении
    // и растягиваем со сглаживанием.
    const nn = valued.length > 1 ? valued.map((a) => Math.min(...valued.filter((q) => q !== a).map((q) => Math.hypot(a.px - q.px, a.py - q.py)))).sort((a, b) => a - b) : [];
    const med = nn.length ? nn[Math.floor(nn.length / 2)] : 0.25 * Math.min(w, h);
    const R = clamp(med * 1.3, 30, 0.4 * Math.max(w, h)), soft = 0.3 * R;
    const step = 4, gw = Math.ceil(w / step), gh = Math.ceil(h / step);
    const off = document.createElement('canvas');
    off.width = gw; off.height = gh;
    const octx = off.getContext('2d');
    const im = octx.createImageData(gw, gh);
    for (let gy = 0; gy < gh; gy++) {
      for (let gx = 0; gx < gw; gx++) {
        const cx = (gx + 0.5) * step, cy = (gy + 0.5) * step;
        let num = 0, den = 0, dmin = 1e9, exact = null;
        for (const q of valued) {
          const d2 = (q.px - cx) ** 2 + (q.py - cy) ** 2;
          if (d2 < 1) { exact = q.v; dmin = 0; break; }
          num += q.v / d2; den += 1 / d2;
          if (d2 < dmin) dmin = d2;
        }
        const dist = exact !== null ? 0 : Math.sqrt(dmin);
        if (dist > R) continue;
        const [r, g, b] = svRgb(exact !== null ? exact : num / den);
        const k = (gy * gw + gx) * 4;
        im.data[k] = r; im.data[k + 1] = g; im.data[k + 2] = b;
        im.data[k + 3] = Math.round(255 * alpha * clamp((R - dist) / soft, 0, 1));
      }
    }
    octx.putImageData(im, 0, 0);
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(off, 0, 0, w, h);
  }
  const showV = S.svVals !== false;
  svg.innerHTML = pts.map(({p, v, px, py}) => {
    const sel = S.svSel === p.id ? ' sel' : '';
    if (p.status === 'pending') return `<g class="spt pending${sel}"><circle cx="${px}" cy="${py}" r="8"/><title>Точка ${p.id}: идёт скан…</title></g>`;
    if (p.status === 'failed') return `<g class="spt failed${sel}" data-pid="${p.id}"><circle cx="${px}" cy="${py}" r="7"/><title>Точка ${p.id}: ошибка скана</title></g>`;
    const fill = v == null ? 'var(--mut)' : svColor(v, 1);
    return `<g class="spt${sel}" data-pid="${p.id}"><circle cx="${px}" cy="${py}" r="6.5" style="fill:${fill}"/>` +
      (showV ? `<text x="${px + 9}" y="${py + 4}">${esc(svFmt(v))}</text>` : '') + `<title>Точка ${p.id}: ${esc(svFmt(v))}</title></g>`;
  }).join('');
  const sv = S.data.survey || {};
  $('svInfo').textContent = `точек: ${sv.points || 0}${sv.pending ? `, ждут скан: ${sv.pending}` : ''}`;
  svSide();
}

function svSide() {
  const side = $('svSide');
  if (!side) return;
  const p = ((S.survey && S.survey.points) || []).find((q) => q.id === S.svSel);
  if (!p) {
    const pts = (S.survey && S.survey.points) || [];
    const vals = pts.map((q) => svValue(q, S.svLayer)).filter((v) => v != null);
    const isCnt = S.svLayer.startsWith('cnt:');
    const bad = vals.filter((v) => isCnt ? v < 2 : v < -72).length;
    side.innerHTML = vals.length ? `<div class="sub">Сводка по слою</div><dl class="kv small">` +
      `<dt>Точек с данными</dt><dd>${vals.length}</dd>` +
      (isCnt ? `<dt>Без запасной AP</dt><dd>${bad} (${Math.round(bad / vals.length * 100)}%)</dd>`
        : `<dt>Лучшая</dt><dd>${svFmt(Math.max(...vals))} дБм</dd><dt>Худшая</dt><dd>${svFmt(Math.min(...vals))} дБм</dd>` +
          `<dt>Слабее −72</dt><dd>${bad} (${Math.round(bad / vals.length * 100)}%)</dd>`) + '</dl>' +
      '<p class="mut small">Нажми на точку в режиме «Просмотр», чтобы увидеть, что слышно в ней.</p>'
      : '<p class="mut small">Точек с данными пока нет.</p>';
    return;
  }
  const res = Object.entries(p.results || {}).sort((a, b) => b[1][3] - a[1][3]).slice(0, 12);
  side.innerHTML = `<div class="sub">Точка ${p.id}</div><dl class="kv small"><dt>Время</dt><dd>${fmtClock(p.t)}</dd>` +
    `<dt>Подключение</dt><dd>${p.conn ? esc(p.conn.ssid) + ', ' + sigSpan(p.conn.rssi, ' дБм') : 'нет'}</dd>` +
    `<dt>Слышно BSS</dt><dd>${Object.keys(p.results || {}).length}</dd></dl>` +
    `<table class="mini"><tbody>${res.map(([b, v]) => `<tr><td>${esc(v[0])}</td><td class="mono">${esc(b.slice(-8))}</td><td>${esc(v[1])}/${v[2]}</td><td class="num">${sigSpan(v[3])}</td></tr>`).join('')}</tbody></table>` +
    `<div class="toolbar"><button type="button" class="small" data-sv="del">Удалить точку</button></div>`;
}

function renderSurveyPanel(body) {
  const sv = S.data.survey || {};
  const key = [sv.has_plan, sv.plan_rev, S.svMode, S.svLayer, DARK, layersKey()].join('|');
  if (body.dataset.svKey === key && $('svImg')) {        // структура та же - обновляем только слой и точки
    svFetchPoints().then(() => { const k2 = layersKey(); if (k2 !== key.split('|').pop()) { body.dataset.svKey = ''; renderPanel(); } else svDraw(); });
    return;
  }
  body.innerHTML = renderSurveyShell();
  body.dataset.svKey = [sv.has_plan, sv.plan_rev, S.svMode, S.svLayer, DARK, layersKey()].join('|');
  if (!sv.has_plan) return;
  Promise.all([svPlanUrl(), svFetchPoints()]).then(([url, changed]) => {
    const img = $('svImg');
    if (!img) return;
    if (changed && layersKey() !== body.dataset.svKey.split('|').pop()) { body.dataset.svKey = ''; renderPanel(); return; }
    img.onload = svDraw;
    if (img.src !== url) img.src = url; else svDraw();
  }).catch((e) => banner('Обход: ' + e.message, true));
}

function layersKey() { return svLayers().map((l) => l[0]).join(','); }

async function svUploadPlan(file) {
  if (!/^image\/(png|jpeg)$/.test(file.type)) { banner('План должен быть PNG или JPG.', true); return; }
  if (file.size > 8 * 1024 * 1024) { banner('План больше 8 МБ: уменьши картинку.', true); return; }
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
  const r = await api('/api/survey/plan', {mime: file.type, data: btoa(bin), name: file.name.replace(/\.[^.]+$/, '')});
  if (!r.ok) { banner('План не загружен: ' + ((r.data && r.data.error) || r.status), true); return; }
  S.survey = null; S.svSel = null;
  await refresh();
  renderPanel();
}

async function svClick(ev) {
  const img = $('svImg');
  if (!img || !img.naturalWidth) return;
  const rc = img.getBoundingClientRect();
  const x = (ev.clientX - rc.left) / rc.width, y = (ev.clientY - rc.top) / rc.height;
  if (x < 0 || x > 1 || y < 0 || y > 1) return;
  if (S.svMode === 'view') {
    const pts = (S.survey && S.survey.points) || [];
    let best = null, bd = 16;
    for (const p of pts) { const d = Math.hypot(p.x * rc.width - (ev.clientX - rc.left), p.y * rc.height - (ev.clientY - rc.top)); if (d < bd) { bd = d; best = p; } }
    S.svSel = best ? best.id : null;
    svDraw();
    return;
  }
  const r = await api('/api/survey/point', {x, y});
  if (!r.ok) { banner('Точка не добавлена: ' + ((r.data && r.data.error) || r.status), true); return; }
  await refresh();
  renderPanel();
}

function svExportPng() {
  const img = $('svImg'), cv = $('svHeat');
  if (!img || !img.naturalWidth) return;
  const W = img.naturalWidth, H = img.naturalHeight, k = W / img.clientWidth;
  const out = document.createElement('canvas');
  out.width = W; out.height = H + 40;
  const c = out.getContext('2d');
  c.fillStyle = '#fff'; c.fillRect(0, 0, W, H + 40);
  c.drawImage(img, 0, 0, W, H);
  c.drawImage(cv, 0, 0, W, H);
  for (const p of (S.survey && S.survey.points) || []) {
    const v = svValue(p, S.svLayer);
    c.beginPath(); c.arc(p.x * W, p.y * H, 6.5 * k, 0, 7);
    c.fillStyle = v == null ? '#888' : svColor(v, 1); c.fill();
    c.lineWidth = 2 * k; c.strokeStyle = '#fff'; c.stroke();
    if (S.svVals !== false) { c.fillStyle = '#111'; c.font = `${Math.round(12 * k)}px Segoe UI, sans-serif`; c.fillText(svFmt(v), p.x * W + 9 * k, p.y * H + 4 * k); }
  }
  const lay = svLayers().find(([key]) => key === S.svLayer);
  c.fillStyle = '#111'; c.font = '16px Segoe UI, sans-serif';
  c.fillText(`${(S.data.survey || {}).name || 'Обход'} · ${lay ? lay[1] : ''} · ${new Date().toLocaleString('ru-RU')}`, 10, H + 26);
  out.toBlob((blob) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = 'wifi-survey-map.png';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  });
}

function renderFindings() {
  const fs = S.data.findings;
  if (!fs.length) return '<p class="mut">По заданным правилам проблем не найдено.</p>';
  const SEV = {critical: 'Критично', warning: 'Внимание', info: 'Информация'};
  const hint = `<div class="toolbar"><span class="mut">${S.hl.size ? `Подсвечено в таблице: ${S.hl.size} BSS.` : 'Нажми на находку, чтобы подсветить затронутые BSS в таблице.'}</span>` +
    `${S.hl.size ? '<button type="button" class="small" id="clrHl">Сбросить</button>' : ''}</div>`;
  return hint + fs.map((f, i) => `
    <div class="f ${f.severity}${i === S.hlIdx ? ' on' : ''}" data-i="${i}" tabindex="0">
      <span class="t">${esc(f.title)}</span><span class="code">${esc(SEV[f.severity] || f.severity)}, ${esc(f.code)}</span>
      <div>${esc(f.detail)}</div>
      ${f.recommendation ? `<div class="rec">Что проверить: ${esc(f.recommendation)}</div>` : ''}
      <div class="mut mono">BSS: ${f.bssids.length}</div>
    </div>`).join('');
}

// ---------- beacon ----------
function renderBeacon() {
  const b = S.data.bss.find((x) => x.bssid === S.sel);
  if (!b) return '<p class="mut">Выбери строку в таблице: здесь появятся все поля beacon с расшифровкой.</p>';
  const tree = b.ie_tree || [];
  if (S.ieFor !== b.bssid || !S.ieOpen) {
    S.ieFor = b.bssid;
    S.ieOpen = new Set(tree.map((ie, i) => (OPEN_IE.includes(ie.id) ? i : -1)).filter((i) => i >= 0));
  }
  const yn = (v) => v ? 'да' : 'нет';
  const rows = [
    ['SSID', b.ssid], ['BSSID', b.bssid + (b.random_mac ? ' (локально администрируемый)' : '')],
    ['Вендор', b.vendor || '—'],
    ['Диапазон и канал', `${b.band} ГГц, канал ${b.channel}, ширина ${b.width} МГц, центр ${b.center}`],
    ['Сигнал', {h: `${sigSpan(b.rssi, ' дБм')}, качество по драйверу ${b.quality}%`}],
    ['Поколение', `${b.gen}${b.streams ? ', потоков: ' + b.streams : ''}`],
    ['Макс. MCS', b.mcs == null ? (b.phy === 'legacy' ? 'legacy (без HT/VHT/HE)' : '—') : `${b.phy} MCS 0–${b.mcs}, потоков ${b.nss}`],
    ['Макс. PHY-скорость', b.rate == null ? '—' : `${b.rate} Мбит/с на ${b.width} МГц (потолок по beacon, не текущая скорость)`],
    ['BSS Color', b.bss_color == null ? '—' : String(b.bss_color)],
    ['Безопасность', b.security], ['AKM', b.akm.join(', ') || '—'], ['Шифры', b.ciphers.join(', ') || '—'],
    ['PMF (802.11w)', b.pmf || '—'], ['WPS', yn(b.wps)],
    ['802.11k', yn(b.k) + (b.k ? (b.nr ? ', neighbor report' : ', без neighbor report') : '')],
    ['802.11r', b.r ? 'да, MDID 0x' + b.mdid.toString(16).toUpperCase() : 'нет'], ['802.11v', yn(b.v)],
    ['Загрузка и станции', b.util == null ? 'QBSS Load не вещается' : `${b.util.toFixed(0)}%, станций ${b.stations}`],
    ['Страна', b.country || '—'], ['Beacon interval', `${b.beacon} TU`], ['DTIM', b.dtim == null ? '—' : String(b.dtim)],
    ['Capability', b.cap], ['HT protection', String(b.ht_prot)], ['Размер IE', b.ie_len + ' байт'],
  ];
  const left = '<dl class="kv">' + rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v && v.h ? v.h : esc(v)}</dd>`).join('') + '</dl>';
  const ies = tree.map((ie, i) => {
    const fields = ie.fields.length
      ? `<dl class="kv small">${ie.fields.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : '';
    return `<details class="ie" data-ie="${i}"${S.ieOpen.has(i) ? ' open' : ''}>` +
      `<summary><span class="ieid">${ie.id}</span><b>${esc(ie.name)}</b> <span class="mut">${ie.len} байт${ie.summary ? ':' : ''}</span>` +
      `${ie.summary ? ' <span>' + esc(ie.summary) + '</span>' : ''}</summary>${fields}<pre class="hex">${esc(ie.hex)}</pre></details>`;
  }).join('');
  const bar = `<div class="toolbar"><b>${esc(b.ssid)}</b><span class="mono mut">${esc(b.bssid)}</span><span class="grow"></span>` +
    `<button type="button" class="small" data-ie-all="1">Раскрыть все</button>` +
    `<button type="button" class="small" data-ie-all="0">Свернуть все</button>` +
    `<button type="button" class="small" data-copy="bssid">Копировать BSSID</button>` +
    `<button type="button" class="small" data-copy="text">Копировать расшифровку</button></div>`;
  return bar + `<div class="bgrid"><div>${left}</div><div><div class="sub">Information Elements: ${tree.length}</div>` +
    `${ies || '<p class="mut">IE не найдены</p>'}</div></div>`;
}

function beaconText(b) {
  const lines = [`${b.ssid}  ${b.bssid}  ${b.band} GHz ch ${b.channel} ${b.width} MHz  ${b.rssi} dBm  ${b.security}`,
    b.rate == null ? '' : `max: ${b.phy} MCS ${b.mcs} x${b.nss}, ${b.rate} Mbit/s`, ''];
  for (const ie of b.ie_tree || []) {
    lines.push(`[${ie.id}] ${ie.name} (${ie.len})${ie.summary ? ': ' + ie.summary : ''}`);
    for (const [k, v] of ie.fields) lines.push(`    ${k}: ${v}`);
    lines.push(`    hex: ${ie.hex}`);
  }
  return lines.join('\n');
}

// ---------- сравнение ----------
function renderCompare() {
  const base = S.data.baseline, d = S.data.diff;
  const btns = '<button type="button" class="small" data-base="current">Сделать текущий скан базовым</button>' +
    '<button type="button" class="small" data-base="file">Взять базу из файла снапшота</button>';
  if (!base) {
    return `<p>Сравнение показывает, что изменилось в эфире между двумя сканами: например, до и после правки на контроллере.</p>` +
      `<div class="toolbar">${btns}</div>` +
      `<p class="mut">Зафиксируй базу сейчас, внеси изменения и сделай новый скан. Или возьми сохранённый ранее снапшот.</p>`;
  }
  const head = `<div class="toolbar"><span>База: <b>${esc(fmtDateTime(base.taken_at))}</b>, BSS ${base.count}</span><span class="grow"></span>` +
    `${btns}<button type="button" class="small" data-base="clear">Убрать базу</button></div>`;
  if (!d) return head + '<p class="mut">База совпадает с текущим сканом. Сделай новый скан, и здесь появится разница.</p>';
  const brief = (x) => `<div class="drow"><span class="dot" style="background:${ssidColor(x.ssid)}"></span><b>${esc(x.ssid)}</b> ` +
    `<span class="mono mut">${esc(x.bssid)}</span> ${esc(x.band)} ГГц, канал ${x.channel}, ${sigSpan(x.rssi, ' дБм')}, ${esc(x.security)}</div>`;
  const sec = (title, n, body) => `<div><div class="sub">${title}: ${n}</div>${n ? body : '<div class="mut">нет</div>'}</div>`;
  const changed = d.changed.map((c) => `<div class="drow"><span class="dot" style="background:${ssidColor(c.ssid)}"></span><b>${esc(c.ssid)}</b> ` +
    `<span class="mono mut">${esc(c.bssid)}</span><dl class="chg">${c.changes.map((x) =>
      `<dt>${esc(x.field)}</dt><dd><span class="old">${esc(x.old)}</span> → <b>${esc(x.new)}</b></dd>`).join('')}</dl></div>`).join('');
  const rssi = d.rssi.map((r) => `<div class="drow"><b>${esc(r.ssid)}</b> <span class="mono mut">${esc(r.bssid)}</span> ` +
    `${sigSpan(r.old)} → ${sigSpan(r.new)} дБм <b class="${r.delta < 0 ? 'bad' : 'good'}">${r.delta > 0 ? '+' : ''}${r.delta}</b></div>`).join('');
  return head + `<div class="dgrid">` +
    sec('Изменились настройки', d.changed.length, changed) +
    sec('Появились', d.added.length, d.added.map(brief).join('')) +
    sec('Пропали', d.removed.length, d.removed.map(brief).join('')) +
    sec(`Сигнал изменился на ${d.rssi_delta} дБ и больше`, d.rssi.length, rssi) +
    `</div><p class="mut">Без изменений: ${d.same} BSS. Пропавшая BSS не всегда выключена: слабую точку скан может просто не услышать.</p>`;
}

function diffCount() {
  const d = S.data && S.data.diff;
  return d ? d.added.length + d.removed.length + d.changed.length : 0;
}

function renderPanel() {
  const body = $('panelBody');
  for (const t of document.querySelectorAll('#tabs [role=tab]')) {
    const on = t.dataset.tab === S.tab;
    t.classList.toggle('on', on);
    t.setAttribute('aria-selected', on ? 'true' : 'false');
  }
  $('cntFind').textContent = S.data && S.data.findings.length ? S.data.findings.length : '';
  $('cntDiff').textContent = diffCount() || '';
  if (S.tab !== 'survey') body.dataset.svKey = '';
  if (S.data && S.tab === 'survey') { renderSurveyPanel(body); return; }
  if (!S.data || (!S.data.bss.length && S.tab !== 'conn')) {
    body.innerHTML = '<p class="mut">Данных пока нет. Нажми «Сканировать», и здесь появятся графики.</p>';
    return;
  }
  const fn = {channels: renderChannels, overview: renderOverview, util: renderUtil, signal: renderSignal, conn: renderConn,
    findings: renderFindings, beacon: renderBeacon, compare: renderCompare}[S.tab];
  const top = body.scrollTop;
  body.innerHTML = fn();
  body.scrollTop = top;
}

function renderAll() {
  renderHead(); renderTable(); renderStrip(); renderPanel();
  $('onlyFocusWrap').hidden = !(S.data && S.data.focus.length);
}

// ---------- меню «Вид» ----------
function renderViewMenu() {
  $('themes').innerHTML = THEMES.map((t) =>
    `<button type="button" data-theme-id="${t.id}" class="${P.theme === t.id ? 'on' : ''}" aria-pressed="${P.theme === t.id}">` +
    `<span class="sw">${t.c.map((c) => `<i style="background:${c}"></i>`).join('')}</span>${esc(t.name)}</button>`).join('');
  $('colList').innerHTML = COLS.filter((c) => !c.fixed).map((c) =>
    `<label class="chk"><input type="checkbox" data-col="${c.k}"${P.cols.includes(c.k) ? ' checked' : ''}> ${esc(c.t)}</label>`).join('');
  for (const r of document.querySelectorAll('input[name=density]')) r.checked = r.value === P.density;
}

// ---------- сеть ----------
// src: откуда сообщение. Плашки «scan» и «link» снимает сама программа, когда проблема ушла;
// остальные ошибки (экспорт, обход) висят, пока их не закроют или не появится новое сообщение.
function banner(msg, isErr, action, src) {
  const b = $('banner');
  b.hidden = !msg;
  b.className = 'banner' + (isErr ? ' err' : '');
  b.dataset.src = src || '';
  b.textContent = msg || '';
  if (msg && action) {
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'small'; btn.textContent = action.label;
    btn.addEventListener('click', action.run);
    b.append(' ', btn);
  }
  if (msg && isErr && !src) {
    const x = document.createElement('button');
    x.type = 'button'; x.className = 'bclose'; x.title = 'Закрыть'; x.textContent = '×';
    x.addEventListener('click', () => banner(''));
    b.append(x);
  }
}
let noteTimer = null;
function note(msg) { banner(msg, false); clearTimeout(noteTimer); noteTimer = setTimeout(() => { if ($('banner').textContent === msg) banner(''); }, 2500); }

function fmtTime(iso) { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleTimeString('ru-RU'); }
function fmtDateTime(iso) { const d = new Date(iso); return isNaN(d) ? String(iso) : d.toLocaleString('ru-RU'); }

function handleState(d) {
  const prevIfaces = S.data ? JSON.stringify(S.data.interfaces) : '';
  S.data = d;
  if (!S.sel || !d.bss.some((b) => b.bssid === S.sel)) {
    const first = visibleBss()[0] || d.bss[0];
    S.sel = first ? first.bssid : null;
  }
  if (prevIfaces !== JSON.stringify(d.interfaces)) {
    $('iface').innerHTML = d.interfaces.map((n, i) => `<option value="${i}">${esc(n)}</option>`).join('');
  }
  $('scan').disabled = d.scanning;
  $('scan').textContent = d.scanning ? 'Сканирую…' : 'Сканировать';
  $('status').textContent = d.taken_at ? `обновлено ${fmtTime(d.taken_at)}` : '';
  if (d.error) banner('Ошибка скана: ' + d.error, true, null, 'scan');
  else if (d.interfaces_error && !d.taken_at) banner('Адаптеры недоступны: ' + d.interfaces_error, true, null, 'scan');
  else if (['scan', 'link'].includes($('banner').dataset.src)) banner('');
  if (document.activeElement !== $('focus')) $('focus').value = d.focus.join(', ');
  const cs = d.conn && d.conn.samples, sv = d.survey || {};
  const sig = JSON.stringify([d.scan_count, d.scanning, d.error, d.taken_at, d.focus, d.weak_rssi, S.sel, d.baseline,
    d.conn && d.conn.current && d.conn.current.bssid, sv.rev]);
  if (sig !== S.sig) { S.sig = sig; renderAll(); }
  else if (S.tab === 'conn' && cs && cs.length && cs[cs.length - 1][0] !== S.connT) renderPanel();   // журнал живёт раз в секунду
  if (cs && cs.length) S.connT = cs[cs.length - 1][0];
}

async function refresh() {
  try {
    const r = await api('/api/state');
    if (!r.ok) throw new Error((r.data && r.data.error) || 'HTTP ' + r.status);
    handleState(r.data);
    return true;
  } catch (e) {
    banner('Нет связи с программой: ' + e.message, true, null, 'link');
    return false;
  }
}

async function startScan() {
  if (S.data && S.data.scanning) return;
  S.lastScan = Date.now();
  const r = await api('/api/scan', {interface: parseInt($('iface').value || '0', 10), wait: 4});
  if (r.status !== 202 && r.status !== 409) banner('Не удалось запустить скан: ' + ((r.data && r.data.error) || r.status), true);
  refresh();
}

async function saveFocus() {
  const list = $('focus').value.split(',').map((s) => s.trim()).filter(Boolean);
  await api('/api/config', {focus: list});
  S.hl.clear(); S.hlIdx = -1;
  refresh();
}

async function doDownload(path, fallback) {
  const r = await api(path, undefined, true);
  if (!r.ok) {
    let msg = 'HTTP ' + r.status;
    try { msg = (await r.json()).error || msg; } catch (e) { /* не JSON */ }
    banner('Не удалось скачать: ' + msg, true);
    return;
  }
  const blob = await r.blob();
  const m = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : fallback;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// Запасной путь для PDF: открыть HTML-отчёт в отдельном окне, дальше Ctrl+P → «Сохранить как PDF».
async function openPrintable(body) {
  const w = window.open('', '_blank');
  const r = await api('/api/export/html', body, true);
  if (!r.ok) { if (w) w.close(); banner('Не удалось подготовить отчёт: HTTP ' + r.status, true); return; }
  const url = URL.createObjectURL(new Blob([await r.text()], {type: 'text/html'}));
  if (w) w.location = url; else window.open(url, '_blank');
  banner('Отчёт открыт в новом окне: нажми Ctrl+P и выбери «Сохранить как PDF».', false);
  setTimeout(() => URL.revokeObjectURL(url), 120000);
}

async function doExport(fmt) {
  if (fmt === 'journal') return doDownload('/api/export/journal', 'wifi-journal.csv');
  if (fmt === 'pdf') banner('Готовлю PDF через Edge, это займёт несколько секунд…', false);
  // «Как в таблице» передаёт ровно те строки, что видны сейчас: с фильтрами, поиском и «Только мои»
  const sc = P.expScope || 'table';
  const body = sc === 'table' ? {scope: 'list', bssids: visibleBss().map((b) => b.bssid)} : {scope: sc};
  let r;
  try {
    r = await api('/api/export/' + fmt, body, true);
  } catch (e) {
    banner('Экспорт не удался: программа не ответила (' + e.message + ')', true);
    return;
  }
  if (!r.ok) {
    let msg = 'HTTP ' + r.status, fallback = '';
    try { const j = await r.json(); msg = j.error || msg; fallback = j.fallback || ''; } catch (e) { /* не JSON */ }
    banner('Экспорт не удался: ' + msg, true, fallback === 'html' && fmt === 'pdf'
      ? {label: 'Открыть отчёт для печати (Ctrl+P → «Сохранить как PDF»)', run: () => openPrintable(body)} : null);
    return;
  }
  if (fmt === 'pdf') banner('');
  const blob = await r.blob();
  const m = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : 'wifi-export';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

async function readJsonFile(input) {
  const f = input.files[0];
  input.value = '';
  if (!f) return null;
  return JSON.parse(await f.text());
}

async function setBaseline(body) {
  const r = await api('/api/baseline', body);
  if (!r.ok) banner('Не удалось задать базу: ' + ((r.data && r.data.error) || r.status), true);
  refresh();
}

async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); note(what + ' скопирован в буфер обмена.'); }
  catch (e) { banner('Не удалось скопировать: браузер запретил доступ к буферу обмена.', true); }
}

// ---------- события ----------
function select(bssid) {
  S.sel = bssid;
  renderTable(); renderPanel();
}
function setTab(tab) {
  S.tab = tab; P.tab = tab; savePrefs();
  renderPanel();
}
function closeMenus(except) {
  for (const m of document.querySelectorAll('.menu-list')) if (m !== except) m.hidden = true;
}

async function init() {
  try {      // настройки с прошлого запуска хранит программа
    const r = await api('/api/prefs');
    if (r.ok && r.data && Object.keys(r.data).length) {
      Object.assign(P, r.data);
      normalizePrefs(); applyTheme();
      S.tab = TABS.includes(P.tab) ? P.tab : 'channels';
    }
  } catch (e) { /* останемся на локальных настройках */ }
  renderViewMenu();
  if (P.panelH) $('panel').style.height = P.panelH + 'px', $('panel').style.flexBasis = P.panelH + 'px';
  $('group').checked = !!P.group;

  $('scan').addEventListener('click', startScan);
  $('focus').addEventListener('change', saveFocus);
  $('focus').addEventListener('keydown', (e) => { if (e.key === 'Enter') saveFocus(); });
  $('q').addEventListener('input', (e) => { S.q = e.target.value; renderTable(); });
  $('minRssi').addEventListener('change', (e) => { S.minRssi = parseInt(e.target.value, 10); renderTable(); });
  $('secFilter').addEventListener('change', (e) => { S.sec = e.target.value; renderTable(); });
  $('group').addEventListener('change', (e) => { P.group = e.target.checked; savePrefs(); renderTable(); });
  $('onlyFocus').addEventListener('change', (e) => { S.onlyFocus = e.target.checked; renderTable(); });
  for (const cb of document.querySelectorAll('.band')) {
    cb.addEventListener('change', () => { S.bands[cb.value] = cb.checked; renderTable(); });
  }

  $('thead').addEventListener('click', (e) => {
    const th = e.target.closest('th');
    if (!th) return;
    const k = th.dataset.k;
    S.sort = S.sort.k === k ? {k, dir: -S.sort.dir} : {k, dir: ['rssi', 'rssi_avg', 'util', 'stations', 'seen_pct'].includes(k) ? -1 : 1};
    renderHead(); renderTable();
  });
  $('thead').addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.target.click(); } });

  $('tbody').addEventListener('click', (e) => {
    const g = e.target.closest('tr.grp');
    if (g) { const k = g.dataset.g; if (S.collapsed.has(k)) S.collapsed.delete(k); else S.collapsed.add(k); renderTable(); return; }
    const tr = e.target.closest('tr');
    if (tr) select(tr.dataset.b);
  });
  $('tbody').addEventListener('keydown', (e) => {
    const tr = e.target.closest('tr');
    if (!tr) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); tr.click(); return; }
    let nxt = e.key === 'ArrowDown' ? tr.nextElementSibling : e.key === 'ArrowUp' ? tr.previousElementSibling : null;
    while (nxt && nxt.classList.contains('grp')) nxt = e.key === 'ArrowDown' ? nxt.nextElementSibling : nxt.previousElementSibling;
    if (nxt) {
      e.preventDefault();
      select(nxt.dataset.b);
      const row = $('tbody').querySelector('tr.sel');
      if (row) row.focus();
    }
  });

  $('tabs').addEventListener('click', (e) => {
    const b = e.target.closest('[role=tab]');
    if (b) setTab(b.dataset.tab);
  });
  $('maxBtn').addEventListener('click', () => {
    const on = $('app').classList.toggle('max');
    $('maxBtn').textContent = on ? 'Свернуть' : 'Развернуть';
    $('panelBody').dataset.svKey = '';
    renderPanel();
  });
  $('strip').addEventListener('click', (e) => { const b = e.target.closest('[data-goto]'); if (b) setTab(b.dataset.goto); });

  const body = $('panelBody');
  body.addEventListener('toggle', (e) => {      // запоминаем, какие IE раскрыты, чтобы скан их не схлопывал
    const d = e.target.closest && e.target.closest('details.ie');
    if (!d || !S.ieOpen) return;
    const i = parseInt(d.dataset.ie, 10);
    if (d.open) S.ieOpen.add(i); else S.ieOpen.delete(i);
  }, true);
  body.addEventListener('change', (e) => {
    if (e.target.dataset.heatall) { P.heatAll = e.target.checked; savePrefs(); renderPanel(); }
    if (e.target.id === 'svLayer') { S.svLayer = e.target.value; S.svSel = null; renderPanel(); }
    if (e.target.id === 'svVals') { S.svVals = e.target.checked; svDraw(); }
  });
  body.addEventListener('input', (e) => {
    if (e.target.id === 'svOpacity') { P.svOpacity = +e.target.value; savePrefs(); svDraw(); }
  });
  body.addEventListener('click', (e) => {
    const sv = e.target.closest('[data-sv]');
    if (sv) {
      const a = sv.dataset.sv;
      if (a === 'plan') $('planFile').click();
      else if (a === 'open') $('projFile').click();
      else if (a === 'save') doDownload('/api/survey/project', 'wifi-survey.json');
      else if (a === 'png') svExportPng();
      else if (a === 'max') { $('maxBtn').click(); }
      else if (a === 'clear') { if (S.svConfirm === 'clear') { S.svConfirm = null; api('/api/survey/clear', {}).then(refresh); } else { S.svConfirm = 'clear'; note('Нажми «Удалить все точки» ещё раз, чтобы подтвердить.'); setTimeout(() => { S.svConfirm = null; }, 4000); } }
      else if (a === 'del' && S.svSel != null) { api('/api/survey/delete', {id: S.svSel}).then(() => { S.svSel = null; refresh(); }); }
      return;
    }
    const md = e.target.closest('[data-svmode]');
    if (md) { S.svMode = md.dataset.svmode; S.svSel = null; renderPanel(); return; }
    if (e.target.closest('#svWrap')) { svClick(e); return; }
    const cw = e.target.closest('[data-cwin]');
    if (cw) { P.connWin = +cw.dataset.cwin; savePrefs(); renderPanel(); return; }
    const cf = e.target.closest('[data-cfilter]');
    if (cf) { S.cfilter = cf.dataset.cfilter; renderPanel(); return; }
    const jr = e.target.closest('[data-journal]');
    if (jr) {
      if (jr.dataset.journal === 'csv') doDownload('/api/export/journal', 'wifi-journal.csv');
      else api('/api/conn/clear', {}).then(refresh);
    }
  });
  body.addEventListener('click', (e) => {
    const t = e.target;
    const cb = t.closest('[data-cb]');
    if (cb) { S.cb = cb.dataset.cb; renderPanel(); return; }
    const sgc = t.closest('[data-sigcolor]');
    if (sgc) { P.sigColor = sgc.dataset.sigcolor; savePrefs(); renderPanel(); return; }
    const sg = t.closest('[data-sig]');
    if (sg) { P.sigMode = sg.dataset.sig; savePrefs(); renderPanel(); return; }
    if (t.closest('[data-hist]')) { doExport('history'); return; }
    if (t.closest('#clrHl')) { S.hl.clear(); S.hlIdx = -1; renderTable(); renderPanel(); return; }
    const all = t.closest('[data-ie-all]');
    const cur = S.data.bss.find((x) => x.bssid === S.sel);
    if (all && cur) {
      S.ieOpen = all.dataset.ieAll === '1' ? new Set((cur.ie_tree || []).map((_, i) => i)) : new Set();
      renderPanel(); return;
    }
    const cp = t.closest('[data-copy]');
    if (cp && cur) { if (cp.dataset.copy === 'bssid') copyText(cur.bssid, 'BSSID'); else copyText(beaconText(cur), 'Текст beacon'); return; }
    const bs = t.closest('[data-base]');
    if (bs) {
      if (bs.dataset.base === 'current') setBaseline({current: true});
      else if (bs.dataset.base === 'clear') setBaseline({clear: true});
      else $('baseFile').click();
      return;
    }
    const f = t.closest('.f');
    if (f) {
      const i = parseInt(f.dataset.i, 10);
      if (S.hlIdx === i) { S.hl.clear(); S.hlIdx = -1; }
      else { S.hlIdx = i; S.hl = new Set(S.data.findings[i].bssids); }
      renderTable(); renderPanel();
      const first = $('tbody').querySelector('tr.hl');
      if (first) first.scrollIntoView({block: 'nearest'});
      return;
    }
    const sh = t.closest('[data-bssid]');
    if (sh) select(sh.dataset.bssid);
  });

  // меню
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-menu]');
    if (btn) { const m = $(btn.dataset.menu); closeMenus(m); m.hidden = !m.hidden; if (!m.hidden && m.id === 'exportMenu') renderExportMenu(); return; }
    // composedPath, а не closest: меню «Вид» перерисовывается при клике, и исходный элемент уже вне документа
    if (!e.composedPath().some((n) => n.classList && n.classList.contains('menu-list'))) closeMenus();
  });
  $('exportMenu').addEventListener('click', (e) => { const b = e.target.closest('button[data-fmt]'); if (b) { closeMenus(); doExport(b.dataset.fmt); } });
  $('exportMenu').addEventListener('change', (e) => { if (e.target.name === 'expScope') { P.expScope = e.target.value; savePrefs(); } });
  $('viewMenu').addEventListener('click', (e) => {
    const t = e.target.closest('[data-theme-id]');
    if (t) { P.theme = t.dataset.themeId; savePrefs(); applyTheme(); renderViewMenu(); renderAll(); }
  });
  $('viewMenu').addEventListener('change', (e) => {
    const c = e.target.dataset.col;
    if (c) {
      P.cols = e.target.checked ? P.cols.concat(c) : P.cols.filter((k) => k !== c);
      savePrefs(); renderHead(); renderTable();
    } else if (e.target.name === 'density') {
      P.density = e.target.value; savePrefs(); applyTheme();
    }
  });
  mq.addEventListener('change', () => { if (P.theme === 'auto') { applyTheme(); renderAll(); } });

  $('load').addEventListener('click', () => $('file').click());
  $('file').addEventListener('change', async (e) => {
    try {
      const body2 = await readJsonFile(e.target);
      if (!body2) return;
      const r = await api('/api/load', body2);
      if (!r.ok) throw new Error((r.data && r.data.error) || 'HTTP ' + r.status);
      $('auto').checked = false;
      S.sel = null; S.hl.clear(); S.hlIdx = -1;
      refresh();
    } catch (err) { banner('Не удалось открыть снапшот: ' + err.message, true); }
  });
  $('baseFile').addEventListener('change', async (e) => {
    try { const b = await readJsonFile(e.target); if (b) setBaseline(b); }
    catch (err) { banner('Не удалось прочитать файл: ' + err.message, true); }
  });

  $('quit').addEventListener('click', async () => {
    await api('/api/quit', {});
    document.body.innerHTML = '<p style="padding:24px;font:14px system-ui">Программа остановлена. Окно можно закрыть.</p>';
    window.close();
  });

  // разделитель между панелью и таблицей
  const rz = $('rz'), panel = $('panel');
  rz.addEventListener('pointerdown', (e) => {
    rz.setPointerCapture(e.pointerId);
    const move = (ev) => {
      const h = clamp(panel.getBoundingClientRect().bottom - ev.clientY, 170, innerHeight - 240);   // панель снизу: тянем её верхний край
      panel.style.height = h + 'px'; panel.style.flexBasis = h + 'px'; P.panelH = Math.round(h);
    };
    const up = () => { rz.removeEventListener('pointermove', move); rz.removeEventListener('pointerup', up); savePrefs(); renderPanel(); };
    rz.addEventListener('pointermove', move);
    rz.addEventListener('pointerup', up);
  });
  $('planFile').addEventListener('change', (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) svUploadPlan(f); });
  $('projFile').addEventListener('change', async (e) => {
    try {
      const b = await readJsonFile(e.target);
      if (!b) return;
      const r = await api('/api/survey/project', b);
      if (!r.ok) throw new Error((r.data && r.data.error) || 'HTTP ' + r.status);
      S.survey = null; S.svSel = null; await refresh(); renderPanel();
    } catch (err) { banner('Проект не открыт: ' + err.message, true); }
  });
  let rsz = null;
  window.addEventListener('resize', () => { clearTimeout(rsz); rsz = setTimeout(renderPanel, 120); });

  // клавиши
  document.addEventListener('keydown', (e) => {
    if (e.key === 'F5') { e.preventDefault(); startScan(); return; }
    const typing = e.target.matches('input[type=text],input[type=search],textarea,select');
    if (e.key === 'Escape') {
      closeMenus();
      if (typing) e.target.blur();
      if (S.q || S.hl.size) { S.q = ''; $('q').value = ''; S.hl.clear(); S.hlIdx = -1; renderTable(); renderPanel(); }
      return;
    }
    if (typing || e.ctrlKey || e.altKey || e.metaKey) return;
    if (e.key === '/') { e.preventDefault(); $('q').focus(); return; }
    const n = parseInt(e.key, 10);
    if (n >= 1 && n <= TABS.length) setTab(TABS[n - 1]);
  });

  // автоскан и опрос состояния
  setInterval(() => {
    if (!$('auto').checked || !S.data || S.data.scanning) return;
    if (Date.now() - S.lastScan >= parseInt($('interval').value, 10) * 1000) startScan();
  }, 1000);
  setInterval(refresh, 1000);
  // окно закрывают - сообщаем серверу, чтобы программа не осталась висеть в фоне (перезагрузка это отменит)
  window.addEventListener('pagehide', () => {
    try { fetch('/api/bye', {method: 'POST', keepalive: true, headers: {'X-Token': TOKEN || ''}}); } catch (e) { /* окно уже закрыто */ }
  });

  refresh().then((ok) => {
    if (ok && S.data && !S.data.taken_at && !S.data.scanning) startScan();
  });
}

init();
})();
