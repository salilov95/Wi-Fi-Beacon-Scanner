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
    /// Точки обхода - целиком (они про маршрут).
    pub survey: &'a [crate::survey::Point],
    pub offset_min: i32,
    /// Версия программы (подпись внизу HTML-отчёта).
    pub version: &'a str,
}

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

/// HTML-отчёт (он же PDF): вёрстка версии 2 - `report_html.rs`.
pub fn render_html(r: &ReportInput) -> String {
    crate::report_html::render_html(r)
}

/// Число разных видимых SSID.
fn ssid_count(bss: &[Bss]) -> usize {
    let mut seen: Vec<String> = bss.iter().filter(|b| !b.hidden()).map(|b| b.ssid_display()).collect();
    seen.sort();
    seen.dedup();
    seen.len()
}

/// Заголовок колонки листа BSS в Excel: по-человечески (в CSV остаются имена полей для скриптов).
fn xlsx_head(c: &str) -> String {
    let (ru, en) = match c {
        "ssid" => ("SSID", "SSID"),
        "bssid" => ("BSSID", "BSSID"),
        "vendor" => ("Вендор", "Vendor"),
        "band_ghz" => ("Диапазон, ГГц", "Band, GHz"),
        "channel" => ("Канал", "Channel"),
        "width_mhz" => ("Ширина, МГц", "Width, MHz"),
        "rssi_dbm" => ("RSSI, дБм", "RSSI, dBm"),
        "link_quality" => ("Качество (драйвер), %", "Link quality (driver), %"),
        "security" => ("Безопасность", "Security"),
        "ciphers" => ("Шифры", "Ciphers"),
        "generation" => ("Поколение", "Generation"),
        "streams" => ("Потоков", "Streams"),
        "phy" => ("PHY", "PHY"),
        "max_mcs" => ("Макс. MCS", "Max MCS"),
        "max_rate_mbps" => ("Макс. PHY, Мбит/с", "Max PHY, Mbit/s"),
        "dot11k" => ("802.11k", "802.11k"),
        "dot11r" => ("802.11r", "802.11r"),
        "dot11v" => ("802.11v", "802.11v"),
        "standards" => ("Дополнения 802.11", "802.11 amendments"),
        "util_pct" => ("Загрузка, %", "Load, %"),
        "stations" => ("Станций", "Stations"),
        "country" => ("Страна", "Country"),
        "beacon_interval" => ("Интервал beacon, TU", "Beacon interval, TU"),
        "dtim" => ("DTIM", "DTIM"),
        other => (other, other),
    };
    crate::app::pick(ru, en)
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
    let mut bss_rows = vec![CSV_COLUMNS
        .iter()
        .map(|&c| Cell::from(xlsx_head(c)))
        .collect::<Vec<_>>()];
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
    if !r.survey.is_empty() {
        sheets.push((tr("Обход"), survey_rows(r.survey, r.focus, r.offset_min)));
    }
    sheets
}

/// Таблица точек обхода (`survey_rows`): для каждого «моего» SSID лучший сигнал и сколько его BSS слышно от −75.
pub fn survey_rows(points: &[crate::survey::Point], focus: &[String], offset_min: i32) -> Vec<Vec<Cell>> {
    let names: Vec<String> = if focus.is_empty() {
        vec![tr("(все сети)")]
    } else {
        focus.to_vec()
    };
    let mut head: Vec<Cell> = vec![
        tr("Точка").into(),
        "X, %".into(),
        "Y, %".into(),
        tr("Время").into(),
        tr("Статус").into(),
        tr("Подключение").into(),
        tr("RSSI подключения").into(),
    ];
    for n in &names {
        head.push(trf("Лучший RSSI: %s", &[Arg::S(n.clone())]).into());
        head.push(trf("BSS от −75: %s", &[Arg::S(n.clone())]).into());
    }
    let mut rows = vec![head];
    for p in points {
        let status = match p.status.as_str() {
            "done" => tr("готово"),
            "pending" => tr("ожидает скан"),
            "failed" => tr("ошибка"),
            _ => String::new(),
        };
        let (cs, cb, cr) = p.conn.as_ref().map_or((String::new(), String::new(), None), |c| {
            (c.ssid.clone(), c.bssid.clone(), c.rssi)
        });
        let mut row: Vec<Cell> = vec![
            p.id.into(),
            round1(p.x * 100.0).into(),
            round1(p.y * 100.0).into(),
            if p.t != 0.0 {
                iso_naive(p.t, offset_min).replacen('T', " ", 1).into()
            } else {
                Cell::Str(String::new())
            },
            status.into(),
            format!("{cs} {cb}").trim().to_string().into(),
            cr.into(),
        ];
        for n in &names {
            let vals: Vec<i64> = p
                .results
                .iter()
                .filter(|(_, v)| focus.is_empty() || &v.0 == n)
                .map(|(_, v)| v.3)
                .collect();
            row.push(vals.iter().max().copied().into());
            row.push(vals.iter().filter(|&&v| v >= -75).count().into());
        }
        rows.push(row);
    }
    rows
}
