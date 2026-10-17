//! Журнал Windows Microsoft-Windows-WLAN-AutoConfig/Operational: разбор XML события и группировка по стадиям.
//! Перенос `wifi_beacon_scanner/winlog.py`; чтение через wevtapi - в `win_log` (только Windows).
//! Текст события берётся из самой Windows (EvtFormatMessage), номера событий нужны только для группировки и цвета.

use crate::clock::parse_utc;
use crate::json::Value;
use crate::xml;

pub const CHANNEL: &str = "Microsoft-Windows-WLAN-AutoConfig/Operational";
pub const PUBLISHER: &str = "Microsoft-Windows-WLAN-AutoConfig";
/// Пространство имён XML событий Windows.
pub const NS: &str = "http://schemas.microsoft.com/win/2004/08/events/event";

/// Группа события по номеру. Значения - как в 1.x (по-русски): их переводит страница.
pub fn group_of(event_id: i64) -> &'static str {
    match event_id {
        8000..=8003 => "подключение",
        11000..=11002 => "ассоциация",
        11004..=11010 => "безопасность / 4-way",
        12011..=12013 => "802.1X",
        _ => "прочее",
    }
}

pub fn level_ru(level: i64) -> String {
    match level {
        1 => "критично",
        2 => "ошибка",
        3 => "предупреждение",
        4 | 0 => "информация",
        5 => "подробно",
        _ => return level.to_string(),
    }
    .to_string()
}

/// `int()` в Python: пробелы по краям допустимы, пустая строка - 0 (там `or 0`).
fn py_int(s: &str) -> Result<i64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(0);
    }
    t.parse::<i64>().map_err(|_| format!("не число: {s:?}"))
}

/// Событие из XML (`parse_event_xml`). Ошибка - XML не разобран (событие пропускается).
pub fn parse_event_xml(xml_text: &str, message: &str) -> Result<Value, String> {
    let root = xml::parse(xml_text)?;
    let sys = root.child(NS, "System");
    let text_of = |name: &str| {
        sys.and_then(|s| s.child(NS, name))
            .map(|e| e.text.as_str())
            .unwrap_or("0")
    };
    let eid = py_int(text_of("EventID"))?;
    let level = py_int(text_of("Level"))?;
    let tc = sys.and_then(|s| s.child(NS, "TimeCreated"));
    let t = parse_utc(tc.and_then(|e| e.attr("SystemTime")).unwrap_or(""));
    let mut data: Vec<(String, String)> = vec![];
    if let Some(ed) = root.child(NS, "EventData") {
        for d in ed.children_named(NS, "Data") {
            let name = match d.attr("Name").filter(|n| !n.is_empty()) {
                Some(n) => n.to_string(),
                None => format!("Data{}", data.len()),
            };
            let v = d.text.trim().to_string();
            match data.iter_mut().find(|(k, _)| *k == name) {
                Some(slot) => slot.1 = v,
                None => data.push((name, v)),
            }
        }
    }
    let get = |k: &str| data.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
    Ok(Value::Obj(vec![
        ("t".into(), t.into()),
        ("id".into(), eid.into()),
        ("level".into(), level.into()),
        ("level_ru".into(), level_ru(level).into()),
        ("group".into(), group_of(eid).into()),
        ("message".into(), message.trim().into()),
        ("ssid".into(), get("SSID").unwrap_or_default().into()),
        (
            "bssid".into(),
            get("BSSID").or_else(|| get("PeerMac")).unwrap_or_default().into(),
        ),
        (
            "reason".into(),
            get("Reason")
                .or_else(|| get("FailureReason"))
                .unwrap_or_default()
                .into(),
        ),
        (
            "data".into(),
            Value::Obj(data.into_iter().map(|(k, v)| (k, v.into())).collect()),
        ),
    ]))
}
