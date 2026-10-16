//! Выгрузки без отчётов: CSV со списком BSS, CSV истории, снапшот JSON.
//! Перенос `render_csv`, `render_history_csv` из `wifi_beacon_scanner/report.py` и `Snapshot.to_json`.
//! HTML-, PDF- и Excel-отчёты в 2.x ещё не перенесены.

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

fn csv_row(b: &Bss) -> Vec<String> {
    let i = &b.info;
    let cap = capability(i);
    vec![
        b.ssid_display(),
        b.bssid.clone(),
        b.vendor.clone().unwrap_or_default(),
        b.band().into(),
        b.channel().to_string(),
        i.width_mhz().to_string(),
        b.rssi.to_string(),
        b.link_quality.to_string(),
        b.security(),
        b.ciphers().join("/"),
        b.generation_label(),
        match i.max_streams() {
            0 => String::new(),
            n => n.to_string(),
        },
        cap.phy.into(),
        opt(cap.mcs),
        cap.rate.map(|r| py_float(round1(r))).unwrap_or_default(),
        yes(i.dot11k()),
        yes(i.dot11r()),
        yes(i.dot11v()),
        short(&standards(b)),
        i.qbss_util_pct.map(py_float).unwrap_or_default(),
        opt(i.qbss_stations),
        i.country.clone().unwrap_or_default(),
        b.beacon_interval.to_string(),
        opt(i.dtim_period),
    ]
}

/// CSV со списком BSS (разделитель `;`, строки `\r\n`), отсортирован как в 1.x.
pub fn render_csv(bss: &[Bss]) -> String {
    let mut rows: Vec<&Bss> = bss.iter().collect();
    rows.sort_by(|a, b| {
        (a.ssid_display().to_lowercase(), a.band(), a.channel(), -a.rssi).cmp(&(
            b.ssid_display().to_lowercase(),
            b.band(),
            b.channel(),
            -b.rssi,
        ))
    });
    let mut out = line(CSV_COLUMNS);
    for b in rows {
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

/// Таблица сессий (`session_rows`): заголовок и строки; пустая ячейка - `""` (в 1.x `None`).
pub fn session_rows(sessions: &[&crate::session::Session], offset_min: i32) -> Vec<Vec<String>> {
    let mut rows = vec![SESSION_HEAD.iter().map(|h| crate::i18n::tr(h)).collect::<Vec<_>>()];
    for s in sessions {
        rows.push(vec![
            iso_naive(s.t_start, offset_min).replacen('T', " ", 1),
            tr_or(session_kind_ru(&s.kind), &s.kind),
            tr_or(session_result_ru(&s.result), &s.result),
            s.ssid.clone(),
            s.bssid_from.clone(),
            s.bssid.clone(),
            opt(s.assoc_ms()),
            opt(s.auth_ms()),
            opt(s.total_ms()),
            opt(s.ip_ms()),
            s.ip.clone(),
            s.dhcp_server.clone(),
            s.ip_note.clone(),
            s.eap_name(),
            s.onex_identity_text(),
            s.onex_status_text(),
            s.reason.clone(),
            s.reason_code
                .filter(|&c| c != 0)
                .map(|c| format!("0x{c:X}"))
                .unwrap_or_default(),
            s.onex_error_code
                .filter(|&c| c != 0)
                .map(|c| format!("0x{c:08X} {}", s.onex_error).trim().to_string())
                .unwrap_or_default(),
        ]);
    }
    rows
}

/// CSV сессий (`render_sessions_csv`).
pub fn render_sessions_csv(sessions: &[&crate::session::Session], offset_min: i32) -> String {
    session_rows(sessions, offset_min).iter().map(|r| line(r)).collect()
}
