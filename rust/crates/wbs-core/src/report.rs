//! Выгрузки и отчёты: CSV (BSS, история, журнал, сессии), снапшот JSON, HTML-отчёт (он же основа PDF), Excel.
//! Перенос `wifi_beacon_scanner/report.py` и `Snapshot.to_json`.

use crate::amend::{short, standards};
use crate::clock::iso_naive;
use crate::i18n::py_float;
use crate::ie::round1;
use crate::json::Value;
use crate::mcs::capability;
use crate::model::{Bss, Snapshot};
use crate::rules::History;

pub const CSV_COLUMNS: &[&str] = &[
    "ssid",
    "bssid",
    "vendor",
    "band_ghz",
    "channel",
    "width_mhz",
    "rssi_dbm",
    "link_quality",
    "security",
    "ciphers",
    "generation",
    "streams",
    "phy",
    "max_mcs",
    "max_rate_mbps",
    "dot11k",
    "dot11r",
    "dot11v",
    "standards",
    "util_pct",
    "stations",
    "country",
    "beacon_interval",
    "dtim",
];

/// Поле как у `csv.writer(delimiter=";")` с QUOTE_MINIMAL.
fn field(s: &str) -> String {
    if s.contains([';', '"', '\r', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn line<S: AsRef<str>>(cells: &[S]) -> String {
    let mut out = cells.iter().map(|c| field(c.as_ref())).collect::<Vec<_>>().join(";");
    out.push_str("\r\n");
    out
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

fn yes(v: bool) -> String {
    (if v { "yes" } else { "no" }).into()
}

/// Значение ячейки для CSV и Excel - как значения Python в строках `_row`, `session_rows`.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// `None` или `""`: в CSV - пусто, в Excel - пустая ячейка.
    Empty,
    Str(String),
    Int(i64),
    Num(f64),
    Bool(bool),
}

impl Cell {
    /// Как `str(v)` в Python (так пишет csv.writer).
    pub fn text(&self) -> String {
        match self {
            Cell::Empty => String::new(),
            Cell::Str(s) => s.clone(),
            Cell::Int(n) => n.to_string(),
            Cell::Num(x) => py_float(*x),
            Cell::Bool(b) => (if *b { "True" } else { "False" }).into(),
        }
    }
}

impl From<String> for Cell {
    fn from(s: String) -> Self {
        Cell::Str(s)
    }
}
impl From<&str> for Cell {
    fn from(s: &str) -> Self {
        Cell::Str(s.into())
    }
}
macro_rules! cell_int {
    ($($t:ty),*) => {$(impl From<$t> for Cell { fn from(n: $t) -> Self { Cell::Int(n as i64) } })*};
}
cell_int!(i32, i64, u8, u16, u32, u64, usize);
impl From<f64> for Cell {
    fn from(x: f64) -> Self {
        Cell::Num(x)
    }
}
impl<T: Into<Cell>> From<Option<T>> for Cell {
    fn from(o: Option<T>) -> Self {
        o.map_or(Cell::Empty, Into::into)
    }
}

/// Строка BSS для CSV и листа «BSS» в Excel (`_row` в report.py).
pub fn bss_cells(b: &Bss) -> Vec<Cell> {
    let i = &b.info;
    let cap = capability(i);
    let streams = i.max_streams();
    vec![
        b.ssid_display().into(),
        b.bssid.as_str().into(),
        b.vendor.clone().unwrap_or_default().into(),
        b.band().into(),
        b.channel().into(),
        i.width_mhz().into(),
        b.rssi.into(),
        b.link_quality.into(),
        b.security().into(),
        b.ciphers().join("/").into(),
        b.generation_label().into(),
        if streams == 0 {
            Cell::Str(String::new())
        } else {
            streams.into()
        },
        cap.phy.into(),
        cap.mcs.into(),
        cap.rate.map(round1).into(),
        yes(i.dot11k()).into(),
        yes(i.dot11r()).into(),
        yes(i.dot11v()).into(),
        short(&standards(b)).into(),
        i.qbss_util_pct.into(),
        i.qbss_stations.into(),
        i.country.clone().unwrap_or_default().into(),
        b.beacon_interval.into(),
        i.dtim_period.into(),
    ]
}

fn csv_row(b: &Bss) -> Vec<String> {
    bss_cells(b).iter().map(Cell::text).collect()
}

/// BSS в порядке отчётов: SSID без учёта регистра, диапазон, канал, сильнее - выше.
pub fn sorted_bss(bss: &[Bss]) -> Vec<&Bss> {
    let mut rows: Vec<&Bss> = bss.iter().collect();
    rows.sort_by(|a, b| {
        (a.ssid_display().to_lowercase(), a.band(), a.channel(), -a.rssi).cmp(&(
            b.ssid_display().to_lowercase(),
            b.band(),
            b.channel(),
            -b.rssi,
        ))
    });
    rows
}

/// CSV со списком BSS (разделитель `;`, строки `\r\n`), отсортирован как в 1.x.
pub fn render_csv(bss: &[Bss]) -> String {
    let mut out = line(CSV_COLUMNS);
    for b in sorted_bss(bss) {
        out.push_str(&line(&csv_row(b)));
    }
    out
}

/// CSV истории замеров; `names` - BSSID -> (SSID, диапазон, канал) из текущего снапшота.
pub fn render_history_csv(history: &History, snap: &Snapshot, offset_min: i32) -> String {
    let mut out = line(&["time", "ssid", "bssid", "band_ghz", "channel", "rssi_dbm", "util_pct"]);
    let mut keys: Vec<&String> = history.keys().collect();
    keys.sort();
    for k in keys {
        let (ssid, band, ch) = snap
            .bss
            .iter()
            .rev() // dict в Python: при повторе BSSID берётся последний
            .find(|b| &b.bssid == k)
            .map(|b| (b.ssid_display(), b.band().to_string(), b.channel().to_string()))
            .unwrap_or_default();
        for (t, r, u) in &history[k] {
            out.push_str(&line(&[
                iso_naive(*t, offset_min),
                ssid.clone(),
                k.clone(),
                band.clone(),
                ch.clone(),
                r.to_string(),
                u.map(py_float).unwrap_or_default(),
            ]));
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Снапшот в формате «Экспорт → JSON» (version 1); его читают и 1.x, и 2.x.
pub fn snapshot_json(s: &Snapshot) -> String {
    let bss = s
        .bss
        .iter()
        .map(|b| {
            Value::Obj(vec![
                ("bssid".into(), b.bssid.as_str().into()),
                ("ssid_hex".into(), hex(&b.ssid_bytes).into()),
                ("rssi".into(), b.rssi.into()),
                ("link_quality".into(), b.link_quality.into()),
                ("freq_khz".into(), b.freq_khz.into()),
                ("beacon_interval".into(), b.beacon_interval.into()),
                ("capability".into(), b.capability.into()),
                ("phy_type".into(), b.phy_type.into()),
                ("ie_hex".into(), hex(&b.ie_raw).into()),
            ])
        })
        .collect();
    Value::Obj(vec![
        ("version".into(), Value::Int(crate::model::SNAPSHOT_VERSION)),
        ("taken_at".into(), s.taken_at.as_str().into()),
        ("interface".into(), s.interface.as_str().into()),
        ("bss".into(), Value::Arr(bss)),
    ])
    .to_json()
}

// ---------------------------------------------------------------- журнал подключения и сессии

pub fn journal_kind_ru(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "connected" => "подключение",
        "disconnected" => "обрыв",
        "roam" => "роуминг",
        "ssid_change" => "смена сети",
        "pingpong" => "пинг-понг",
        "sticky" => "залипание",
        "attempt_fail" => "неудачное подключение",
        "disconnect_reason" => "отключение (по данным Windows)",
        _ => return None,
    })
}

fn tr_or(key: Option<&'static str>, raw: &str) -> String {
    match key {
        Some(k) => crate::i18n::tr(k),
        None => crate::i18n::tr(raw),
    }
}

/// CSV журнала подключения (`render_journal_csv`).
pub fn render_journal_csv(events: &[&crate::conn::ConnEvent], offset_min: i32) -> String {
    let mut out = line(&[
        "time",
        "event",
        "ssid",
        "bssid_from",
        "bssid_to",
        "rssi_from",
        "rssi_to",
        "duration_s",
        "reason_code",
        "reason",
        "text",
    ]);
    for e in events {
        out.push_str(&line(&[
            iso_naive(e.t, offset_min),
            tr_or(journal_kind_ru(&e.kind), &e.kind),
            e.ssid.clone(),
            e.bssid_from.clone(),
            e.bssid_to.clone(),
            opt(e.rssi_from),
            opt(e.rssi_to),
            e.duration_s.map(py_float).unwrap_or_default(),
            e.reason_code.map(|c| format!("0x{c:X}")).unwrap_or_default(),
            e.reason.clone(),
            e.text.clone(),
        ]));
    }
    out
}

const SESSION_HEAD: [&str; 19] = [
    "Время",
    "Тип",
    "Итог",
    "SSID",
    "Откуда",
    "Куда",
    "Ассоциация, мс",
    "Аутентификация, мс",
    "Всего, мс",
    "IP через, мс",
    "IPv4",
    "DHCP-сервер",
    "IP/DHCP",
    "EAP",
    "Учётка 802.1X",
    "802.1X",
    "Причина",
    "Код причины",
    "Ошибка EAP",
];

fn session_kind_ru(k: &str) -> Option<&'static str> {
    match k {
        "connect" => Some("подключение"),
        "roam" => Some("роуминг"),
        _ => None,
    }
}

fn session_result_ru(r: &str) -> Option<&'static str> {
    Some(match r {
        "ok" => "успешно",
        "fail" => "ошибка",
        "aborted" => "прервано",
        "in_progress" => "идёт",
        _ => return None,
    })
}

/// Таблица сессий (`session_rows`): заголовок и строки.
pub fn session_rows(sessions: &[&crate::session::Session], offset_min: i32) -> Vec<Vec<Cell>> {
    let mut rows = vec![SESSION_HEAD
        .iter()
        .map(|h| Cell::Str(crate::i18n::tr(h)))
        .collect::<Vec<_>>()];
    for s in sessions {
        rows.push(vec![
            iso_naive(s.t_start, offset_min).replacen('T', " ", 1).into(),
            tr_or(session_kind_ru(&s.kind), &s.kind).into(),
            tr_or(session_result_ru(&s.result), &s.result).into(),
            s.ssid.as_str().into(),
            s.bssid_from.as_str().into(),
            s.bssid.as_str().into(),
            s.assoc_ms().into(),
            s.auth_ms().into(),
            s.total_ms().into(),
            s.ip_ms().into(),
            s.ip.as_str().into(),
            s.dhcp_server.as_str().into(),
            s.ip_note.as_str().into(),
            s.eap_name().into(),
            s.onex_identity_text().into(),
            s.onex_status_text().into(),
            s.reason.as_str().into(),
            s.reason_code.filter(|&c| c != 0).map(|c| format!("0x{c:X}")).into(),
            s.onex_error_code
                .filter(|&c| c != 0)
                .map(|c| format!("0x{c:08X} {}", s.onex_error).trim().to_string())
                .into(),
        ]);
    }
    rows
}

/// CSV сессий (`render_sessions_csv`).
pub fn render_sessions_csv(sessions: &[&crate::session::Session], offset_min: i32) -> String {
    session_rows(sessions, offset_min)
        .iter()
        .map(|r| line(&r.iter().map(Cell::text).collect::<Vec<_>>()))
        .collect()
}

// ---------------------------------------------------------------- HTML-отчёт и Excel

/// Что идёт в отчёт: выбранные сети и то, что к ним относится (`export_view` + extra в 1.x).
pub struct ReportInput<'a> {
    pub snap: &'a Snapshot,
    pub findings: &'a [crate::rules::Finding],
    pub focus: &'a [String],
    pub note: &'a str,
    /// Загрузка каналов по выбранным сетям (`channel_utilization` без истории).
    pub util: Option<&'a Value>,
    /// Журнал подключения и сессии - целиком (они про ноутбук).
    pub journal: Option<&'a crate::conn::ConnTracker>,
    /// История замеров выбранных сетей (только Excel).
    pub history: Option<&'a History>,
    pub offset_min: i32,
}

const CSS: &str = "
:root{--bg:#fff;--fg:#1c1f23;--mut:#5c6670;--line:#d9dee3;--card:#f6f8fa;
--crit:#b3261e;--warn:#9a5b00;--info:#2457a6}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e9ec;--mut:#9aa5b0;--line:#2c333a;--card:#1b2025;
--crit:#ff8a80;--warn:#ffb74d;--info:#8ab4f8}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1200px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.mut{color:var(--mut)}
.sum{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.sum div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:120px}
.sum b{display:block;font-size:24px}
.f{border:1px solid var(--line);border-left-width:4px;border-radius:6px;background:var(--card);padding:10px 14px;margin:8px 0}
.f.critical{border-left-color:var(--crit)}.f.warning{border-left-color:var(--warn)}.f.info{border-left-color:var(--info)}
.f h3{margin:0 0 2px;font-size:15px}.tag{font-size:12px;font-weight:600}
.critical .tag{color:var(--crit)}.warning .tag{color:var(--warn)}.info .tag{color:var(--info)}
.rec{margin-top:4px}code{font-size:12px;color:var(--mut)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{position:sticky;top:0;background:var(--card)}
.ubar{display:inline-block;width:160px;height:10px;background:var(--line);border-radius:3px;overflow:hidden;vertical-align:middle}
.ubar i{display:block;height:100%}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px}
.kv dt{color:var(--mut)}.kv dd{margin:0}
@page{size:A4 landscape;margin:12mm}
@media print{
  :root{--bg:#fff;--fg:#1c1f23;--mut:#5c6670;--line:#d9dee3;--card:#f6f8fa;--crit:#b3261e;--warn:#9a5b00;--info:#2457a6}
  body{padding:0;font-size:11px}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  h2{break-after:avoid}.f,tr{break-inside:avoid}table{font-size:10px}th{position:static}
  .wrap{overflow:visible}td,th{white-space:normal}
}
";

/// `html.escape`: & < > " '.
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn sev_ru(s: &str) -> &'static str {
    match s {
        crate::rules::CRITICAL => "Критично",
        crate::rules::WARNING => "Внимание",
        _ => "Информация",
    }
}

fn util_color(u: f64) -> String {
    let hue = (130.0 * (1.0 - (u / 75.0).clamp(0.0, 1.0))).round_ties_even() as i64;
    format!("hsl({hue} 70% 40%)")
}

const RSSI_STOPS: [(f64, f64); 5] = [
    (-85.0, 0.0),
    (-75.0, 25.0),
    (-67.0, 55.0),
    (-60.0, 95.0),
    (-50.0, 130.0),
];

/// Оттенок сигнала: от красного (плохо) к зелёному (хорошо) - те же точки, что в интерфейсе.
pub fn rssi_hue(r: f64) -> i64 {
    if r <= RSSI_STOPS[0].0 {
        return RSSI_STOPS[0].1 as i64;
    }
    for w in RSSI_STOPS.windows(2) {
        let ((a, ha), (b, hb)) = (w[0], w[1]);
        if r <= b {
            return (ha + (hb - ha) * (r - a) / (b - a)).round_ties_even() as i64;
        }
    }
    RSSI_STOPS[4].1 as i64
}

fn rssi_color(r: f64) -> String {
    format!("hsl({} 72% 36%)", rssi_hue(r))
}

fn rssi_td(v: i64) -> String {
    format!("<td style='color:{};font-weight:600'>{v}</td>", rssi_color(v as f64))
}

use crate::i18n::{pyfmt, tr, trf, Arg};

fn vf(v: Option<&Value>) -> f64 {
    v.and_then(Value::as_f64).unwrap_or(0.0)
}
fn vs(v: Option<&Value>) -> String {
    match v {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Int(n)) => n.to_string(),
        Some(Value::Num(x)) => py_float(*x),
        _ => String::new(),
    }
}
fn vi(v: Option<&Value>) -> i64 {
    v.and_then(|x| x.as_f64()).map_or(0, |x| x as i64)
}

/// HTML-отчёт (`render_html`): сводка, проблемы, загрузка каналов, журнал и сессии, все BSS.
pub fn render_html(r: &ReportInput) -> String {
    let snap = r.snap;
    let count = |sev: &str| r.findings.iter().filter(|f| f.severity == sev).count();
    let mut out: Vec<String> = vec![];
    out.push(trf(
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\"><meta name='viewport' content='width=device-width,initial-scale=1'><title>Wi-Fi Beacon Scanner: отчёт</title><style>%s</style></head><body><main>",
        &[Arg::S(CSS.into())],
    ));
    out.push(tr("<h1>Wi-Fi Beacon Scanner: отчёт</h1>"));
    let focus_note = if r.focus.is_empty() {
        String::new()
    } else {
        tr(" · мои SSID: ") + &esc(&r.focus.join(", "))
    };
    let iface = if snap.interface.is_empty() {
        "-"
    } else {
        &snap.interface
    };
    out.push(trf(
        "<div class='mut'>Снято: %s · адаптер: %s · BSS в отчёте: %d%s</div>",
        &[
            Arg::S(esc(&snap.taken_at)),
            Arg::S(esc(iface)),
            Arg::I(snap.bss.len() as i64),
            Arg::S(focus_note),
        ],
    ));
    if !r.note.is_empty() {
        out.push(trf(
            "<div class='mut'>В отчёт включены: %s</div>",
            &[Arg::S(esc(r.note))],
        ));
    }
    let ssids = ssid_count(&snap.bss);
    out.push(trf(
        "<div class='sum'><div><b>%d</b>BSS</div><div><b>%d</b>SSID</div><div><b>%d</b>Критично</div><div><b>%d</b>Внимание</div><div><b>%d</b>Информация</div></div>",
        &[
            Arg::I(snap.bss.len() as i64),
            Arg::I(ssids as i64),
            Arg::I(count(crate::rules::CRITICAL) as i64),
            Arg::I(count(crate::rules::WARNING) as i64),
            Arg::I(count(crate::rules::INFO) as i64),
        ],
    ));
    out.push(tr("<h2>Проблемы</h2>"));
    if r.findings.is_empty() {
        out.push(tr("<p class='mut'>Проблем по заданным правилам не найдено.</p>"));
    }
    for f in r.findings {
        out.push(format!(
            "<div class='f {}'><span class='tag'>{} · {}</span><h3>{}</h3><div>{}</div>",
            f.severity,
            tr(sev_ru(f.severity)),
            esc(&f.code),
            esc(&f.title),
            esc(&f.detail)
        ));
        if !f.recommendation.is_empty() {
            out.push(trf(
                "<div class='rec'><b>Что проверить:</b> %s</div>",
                &[Arg::S(esc(&f.recommendation))],
            ));
        }
        if !f.bssids.is_empty() {
            let shown: Vec<&str> = f.bssids.iter().take(8).map(String::as_str).collect();
            let more = if f.bssids.len() > 8 {
                format!(" … (+{})", f.bssids.len() - 8)
            } else {
                String::new()
            };
            out.push(format!("<code>{}{more}</code>", esc(&shown.join(", "))));
        }
        out.push("</div>".into());
    }
    if let Some(util) = r.util {
        let channels = util
            .get("channels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !channels.is_empty() {
            out.push(tr("<h2>Загрузка каналов (QBSS Load)</h2><p class='mut'>Доля времени, когда сама AP считает канал занятым; на канал взят максимум среди AP, сообщающих эту цифру.</p>"));
            out.push(tr("<div class='wrap'><table><thead><tr><th>ГГц</th><th>Канал</th><th>Загрузка</th><th></th><th>Уровень</th><th>Среднее</th><th>AP с данными</th><th>Станций</th><th>Самые загруженные</th></tr></thead><tbody>"));
            for ch in &channels {
                let aps = ch.get("aps").and_then(Value::as_array).cloned().unwrap_or_default();
                let top = aps
                    .iter()
                    .take(3)
                    .map(|a| pyfmt("%s %.0f%%", &[Arg::S(vs(a.get("ssid"))), Arg::F(vf(a.get("util")))]))
                    .collect::<Vec<_>>()
                    .join(", ");
                let mx = vf(ch.get("max"));
                out.push(trf(
                    "<tr><td>%s</td><td>%s</td><td><span class='ubar'><i style='width:%.0f%%;background:%s'></i></span></td><td>%.0f%%</td><td>%s</td><td>%.0f%%</td><td>%d из %d</td><td>%d</td><td>%s</td></tr>",
                    &[
                        Arg::S(esc(&vs(ch.get("band")))),
                        Arg::S(vs(ch.get("channel"))),
                        Arg::F(mx.max(1.0)),
                        Arg::S(util_color(mx)),
                        Arg::F(mx),
                        Arg::S(esc(&vs(ch.get("label")))),
                        Arg::F(vf(ch.get("avg"))),
                        Arg::I(vi(ch.get("reporting"))),
                        Arg::I(vi(ch.get("bss"))),
                        Arg::I(vi(ch.get("stations"))),
                        Arg::S(esc(&top)),
                    ],
                ));
            }
            out.push("</tbody></table></div>".into());
            let no_data = util
                .get("no_data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if !no_data.is_empty() {
                let list = no_data
                    .iter()
                    .map(|x| {
                        trf(
                            "%s ГГц канал %s",
                            &[Arg::S(vs(x.get("band"))), Arg::S(vs(x.get("channel")))],
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push(trf(
                    "<p class='mut'>Нет данных QBSS Load: %s.</p>",
                    &[Arg::S(esc(&list))],
                ));
            }
        }
    }
    if let Some(j) = r.journal.filter(|j| !j.events.is_empty()) {
        let st = j.stats();
        out.push(tr("<h2>Подключение ноутбука</h2>"));
        out.push(trf(
            "<dl class='kv'><dt>Роумингов</dt><dd>%d</dd><dt>Обрывов</dt><dd>%d (без связи %.0f с)</dd><dt>Пинг-понгов</dt><dd>%d</dd><dt>Залипаний</dt><dd>%d</dd><dt>Неудачных подключений</dt><dd>%d</dd></dl>",
            &[
                Arg::I(vi(st.get("roams"))),
                Arg::I(vi(st.get("disconnects"))),
                Arg::F(vf(st.get("down_s"))),
                Arg::I(vi(st.get("pingpong"))),
                Arg::I(vi(st.get("sticky"))),
                Arg::I(vi(st.get("attempt_fail"))),
            ],
        ));
        out.push(tr("<div class='wrap'><table><thead><tr><th>Время</th><th>Событие</th><th>SSID</th><th>Откуда</th><th>Куда</th><th>RSSI</th><th>Длительность</th><th>Причина</th></tr></thead><tbody>"));
        let skip = j.events.len().saturating_sub(200);
        for ev in j.events.iter().skip(skip).rev() {
            let rs = [ev.rssi_from, ev.rssi_to]
                .iter()
                .flatten()
                .map(|x| {
                    format!(
                        "<span style='color:{};font-weight:600'>{x}</span>",
                        rssi_color(*x as f64)
                    )
                })
                .collect::<Vec<_>>()
                .join(" → ");
            let dur = ev.duration_s.map(|d| trf("%.0f с", &[Arg::F(d)])).unwrap_or_default();
            out.push(format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{rs}</td><td>{dur}</td><td>{}</td></tr>",
                &iso_naive(ev.t, r.offset_min)[11..19],
                esc(&tr_or(journal_kind_ru(&ev.kind), &ev.kind)),
                esc(&ev.ssid),
                esc(&ev.bssid_from),
                esc(&ev.bssid_to),
                esc(&ev.reason)
            ));
        }
        out.push("</tbody></table></div>".into());
    }
    if let Some(j) = r.journal.filter(|j| !j.sessions.sessions.is_empty()) {
        let skip = j.sessions.sessions.len().saturating_sub(200);
        let ss: Vec<&crate::session::Session> = j.sessions.sessions.iter().skip(skip).rev().collect();
        let rows = session_rows(&ss, r.offset_min);
        const KEEP: [usize; 12] = [0, 1, 2, 4, 5, 6, 7, 8, 9, 13, 15, 16];
        out.push(tr("<h2>Сессии подключения</h2><p class='mut'>Стадии по уведомлениям Windows: ассоциация, аутентификация (802.1X и 4-way handshake), получение IPv4.</p>"));
        out.push(format!(
            "<div class='wrap'><table><thead><tr>{}</tr></thead><tbody>",
            KEEP.iter()
                .map(|&i| format!("<th>{}</th>", esc(&rows[0][i].text())))
                .collect::<String>()
        ));
        for row in &rows[1..] {
            out.push(format!(
                "<tr>{}</tr>",
                KEEP.iter()
                    .map(|&i| format!("<td>{}</td>", esc(&row[i].text())))
                    .collect::<String>()
            ));
        }
        out.push("</tbody></table></div>".into());
    }
    out.push(tr("<h2>Все BSS</h2><div class='wrap'><table><thead><tr>"));
    for name in [
        "SSID",
        "BSSID",
        "Вендор",
        "ГГц",
        "Канал",
        "Ширина",
        "RSSI",
        "Безопасность",
        "Поколение",
        "Макс. MCS",
        "Макс. PHY, Мбит/с",
        "802.11",
        "Загрузка",
        "Станций",
        "Страна",
    ] {
        out.push(format!("<th>{}</th>", esc(&tr(name))));
    }
    out.push("</tr></thead><tbody>".into());
    for b in sorted_bss(&snap.bss) {
        let i = &b.info;
        let cap = capability(i);
        let mcs = cap
            .mcs
            .map_or(String::new(), |m| format!("{} {} x{}", cap.phy, m, cap.nss));
        let rate = cap.rate.map_or(String::new(), |x| pyfmt("%.0f", &[Arg::F(x)]));
        let util = i.qbss_util_pct.map_or(String::new(), |u| pyfmt("%.0f%%", &[Arg::F(u)]));
        let td = |s: String| format!("<td>{}</td>", esc(&s));
        out.push(format!(
            "<tr>{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}</tr>",
            td(b.ssid_display()),
            td(b.bssid.clone()),
            td(b.vendor.clone().unwrap_or_default()),
            td(b.band().into()),
            td(b.channel().to_string()),
            td(i.width_mhz().to_string()),
            rssi_td(b.rssi as i64),
            td(b.security()),
            td(b.generation_label()),
            td(mcs),
            td(rate),
            td(short(&standards(b))),
            td(util),
            td(i.qbss_stations.map(|x| x.to_string()).unwrap_or_default()),
            td(i.country.clone().unwrap_or_default()),
        ));
    }
    out.push("</tbody></table></div></main></body></html>".into());
    out.concat()
}

/// Число разных видимых SSID.
fn ssid_count(bss: &[Bss]) -> usize {
    let mut seen: Vec<String> = bss.iter().filter(|b| !b.hidden()).map(|b| b.ssid_display()).collect();
    seen.sort();
    seen.dedup();
    seen.len()
}

/// Excel-отчёт (`build_xlsx_report`): листы «Сводка», «BSS», «Проблемы», загрузка, история, журнал, сессии.
pub fn build_xlsx_report(r: &ReportInput) -> Result<Vec<u8>, String> {
    crate::xlsx::build_xlsx(&xlsx_sheets(r))
}

/// Листы Excel-отчёта (отдельно - чтобы сверять с 1.x по содержимому).
pub fn xlsx_sheets(r: &ReportInput) -> Vec<crate::xlsx::Sheet> {
    let snap = r.snap;
    let count = |sev: &str| r.findings.iter().filter(|f| f.severity == sev).count();
    let row = |a: Cell, b: Cell| vec![a, b];
    let mut summary = vec![
        row(tr("Параметр").into(), tr("Значение").into()),
        row(tr("Снято").into(), snap.taken_at.as_str().into()),
        row(
            tr("Адаптер").into(),
            (if snap.interface.is_empty() {
                "-"
            } else {
                &snap.interface
            })
            .into(),
        ),
        row(
            tr("В отчёт включены").into(),
            if r.note.is_empty() {
                tr("все сети")
            } else {
                r.note.to_string()
            }
            .into(),
        ),
        row(
            tr("Мои SSID").into(),
            if r.focus.is_empty() {
                "-".to_string()
            } else {
                r.focus.join(", ")
            }
            .into(),
        ),
        row("BSS".into(), snap.bss.len().into()),
        row("SSID".into(), ssid_count(&snap.bss).into()),
        row(tr("Проблемы: критично").into(), count(crate::rules::CRITICAL).into()),
        row(tr("Проблемы: внимание").into(), count(crate::rules::WARNING).into()),
        row(tr("Проблемы: информация").into(), count(crate::rules::INFO).into()),
    ];
    let journal = r.journal.filter(|j| !j.events.is_empty());
    if let Some(j) = journal {
        let st = j.stats();
        let num = |k: &str| match st.get(k) {
            Some(Value::Int(n)) => Cell::Int(*n),
            Some(Value::Num(x)) => Cell::Num(*x),
            _ => Cell::Int(0),
        };
        summary.push(row(tr("Роумингов ноутбука").into(), num("roams")));
        summary.push(row(tr("Обрывов").into(), num("disconnects")));
        summary.push(row(tr("Без связи, с").into(), num("down_s")));
        summary.push(row(tr("Пинг-понгов").into(), num("pingpong")));
        summary.push(row(tr("Залипаний").into(), num("sticky")));
    }
    let mut sheets: Vec<crate::xlsx::Sheet> = vec![(tr("Сводка"), summary)];
    let mut bss_rows = vec![CSV_COLUMNS.iter().map(|&c| Cell::from(c)).collect::<Vec<_>>()];
    bss_rows.extend(sorted_bss(&snap.bss).into_iter().map(bss_cells));
    sheets.push(("BSS".into(), bss_rows));
    let mut fr: Vec<Vec<Cell>> = vec![[
        tr("Важность"),
        tr("Код"),
        tr("Проблема"),
        tr("Подробности"),
        tr("Что проверить"),
        "SSID".into(),
        "BSSID".into(),
    ]
    .into_iter()
    .map(Cell::from)
    .collect()];
    for f in r.findings {
        fr.push(vec![
            tr(sev_ru(f.severity)).into(),
            f.code.as_str().into(),
            f.title.as_str().into(),
            f.detail.as_str().into(),
            f.recommendation.as_str().into(),
            f.ssid.as_str().into(),
            f.bssids.join(", ").into(),
        ]);
    }
    sheets.push((tr("Проблемы"), fr));
    if let Some(util) = r.util {
        let channels = util
            .get("channels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !channels.is_empty() {
            let mut ur: Vec<Vec<Cell>> = vec![[
                "ГГц",
                "Канал",
                "Загрузка макс, %",
                "Загрузка средн, %",
                "Уровень",
                "AP с данными",
                "BSS на канале",
                "Станций",
                "Самые загруженные",
            ]
            .iter()
            .map(|h| Cell::from(tr(h)))
            .collect()];
            for ch in &channels {
                let aps = ch.get("aps").and_then(Value::as_array).cloned().unwrap_or_default();
                let top = aps
                    .iter()
                    .take(5)
                    .map(|a| pyfmt("%s %.0f%%", &[Arg::S(vs(a.get("ssid"))), Arg::F(vf(a.get("util")))]))
                    .collect::<Vec<_>>()
                    .join(", ");
                ur.push(vec![
                    vs(ch.get("band")).into(),
                    Cell::Int(vi(ch.get("channel"))),
                    Cell::Num(vf(ch.get("max"))),
                    Cell::Num(vf(ch.get("avg"))),
                    vs(ch.get("label")).into(),
                    Cell::Int(vi(ch.get("reporting"))),
                    Cell::Int(vi(ch.get("bss"))),
                    Cell::Int(vi(ch.get("stations"))),
                    top.into(),
                ]);
            }
            sheets.push((tr("Загрузка каналов"), ur));
        }
    }
    if let Some(h) = r.history.filter(|h| !h.is_empty()) {
        let mut hr: Vec<Vec<Cell>> = vec![[
            tr("Время"),
            "SSID".into(),
            "BSSID".into(),
            tr("ГГц"),
            tr("Канал"),
            tr("RSSI, дБм"),
            tr("Загрузка, %"),
        ]
        .into_iter()
        .map(Cell::from)
        .collect()];
        let mut keys: Vec<&String> = h.keys().collect();
        keys.sort();
        for k in keys {
            let b = snap.bss.iter().rev().find(|b| &b.bssid == k);
            for (t, rssi, u) in &h[k] {
                hr.push(vec![
                    iso_naive(*t, r.offset_min).replacen('T', " ", 1).into(),
                    b.map_or(Cell::Str(String::new()), |b| b.ssid_display().into()),
                    k.as_str().into(),
                    b.map_or(Cell::Str(String::new()), |b| b.band().into()),
                    b.map_or(Cell::Str(String::new()), |b| b.channel().into()),
                    (*rssi).into(),
                    (*u).into(),
                ]);
            }
        }
        sheets.push((tr("История"), hr));
    }
    if let Some(j) = journal {
        let mut jr: Vec<Vec<Cell>> = vec![[
            "Время",
            "Событие",
            "SSID",
            "Откуда",
            "Куда",
            "RSSI до",
            "RSSI после",
            "Длительность, с",
            "Код причины",
            "Причина",
            "Описание",
        ]
        .iter()
        .map(|h| Cell::from(tr(h)))
        .collect()];
        for ev in &j.events {
            jr.push(vec![
                iso_naive(ev.t, r.offset_min).replacen('T', " ", 1).into(),
                tr_or(journal_kind_ru(&ev.kind), &ev.kind).into(),
                ev.ssid.as_str().into(),
                ev.bssid_from.as_str().into(),
                ev.bssid_to.as_str().into(),
                ev.rssi_from.into(),
                ev.rssi_to.into(),
                ev.duration_s.into(),
                ev.reason_code.map(|c| format!("0x{c:X}")).into(),
                ev.reason.as_str().into(),
                ev.text.as_str().into(),
            ]);
        }
        sheets.push((tr("Журнал подключения"), jr));
    }
    if let Some(j) = r.journal.filter(|j| !j.sessions.sessions.is_empty()) {
        let ss: Vec<&crate::session::Session> = j.sessions.sessions.iter().collect();
        sheets.push((tr("Сессии"), session_rows(&ss, r.offset_min)));
    }
    sheets
}
