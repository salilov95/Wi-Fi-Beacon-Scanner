//! Настройки вида: только известные ключи с допустимыми значениями. Перенос `sanitize_prefs` из
//! `wifi_beacon_scanner/web/state.py`. Файл может править кто угодно, а тема потом подставляется в HTML.

use crate::json::Value;

pub const THEMES: &[&str] = &["auto", "light", "dark", "nord", "solar", "paper", "contrast"];
const TABS: &[&str] = &[
    "channels", "overview", "util", "signal", "conn", "sessions", "winlog", "survey", "findings", "beacon", "compare",
];

fn col_name(s: &str) -> bool {
    (1..=24).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
}

/// Число, но не bool (в Python bool - подкласс int).
fn num(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Int(n)) => Some(*n as f64),
        Some(Value::Num(x)) => Some(*x),
        _ => None,
    }
}

fn one_of<'a>(v: Option<&'a Value>, allowed: &[&str]) -> Option<&'a str> {
    v.and_then(Value::as_str).filter(|s| allowed.contains(s))
}

pub fn sanitize(d: &Value) -> Value {
    let mut out: Vec<(String, Value)> = vec![];
    if !matches!(d, Value::Obj(_)) {
        return Value::Obj(out);
    }
    let mut put = |k: &str, v: Value| out.push((k.to_string(), v));
    for (key, allowed) in [
        ("theme", THEMES),
        ("density", &["normal", "compact"][..]),
        ("tab", TABS),
        ("expScope", &["table", "focus", "all"][..]),
    ] {
        if let Some(s) = one_of(d.get(key), allowed) {
            put(key, s.into());
        }
    }
    // `d.get(k) in (60, 300, ...)`: 300.0 тоже подходит и остаётся числом с точкой, как прислали
    if num(d.get("connWin")).is_some_and(|x| [60.0, 300.0, 900.0, 1800.0].contains(&x)) {
        put("connWin", d.get("connWin").cloned().unwrap_or(Value::Null));
    }
    if let Some(x) = num(d.get("svOpacity")).filter(|x| (0.1..=0.9).contains(x)) {
        // `round(x, 2)` в Python - по точному значению double с половиной к чётному; `{:.2}` округляет так же
        put("svOpacity", format!("{x:.2}").parse::<f64>().unwrap_or(x).into());
    }
    if let Some(s) = one_of(d.get("sigMode"), &["lines", "heat"]) {
        put("sigMode", s.into());
    }
    if let Some(s) = one_of(d.get("sigColor"), &["level", "bss"]) {
        put("sigColor", s.into());
    }
    if let Some(s) = one_of(d.get("lang"), &["ru", "en"]) {
        put("lang", s.into());
    }
    if num(d.get("interval")).is_some_and(|x| [5.0, 10.0, 30.0, 60.0].contains(&x)) {
        put("interval", d.get("interval").cloned().unwrap_or(Value::Null));
    }
    for k in ["group", "heatAll", "auto"] {
        if let Some(Value::Bool(b)) = d.get(k) {
            put(k, Value::Bool(*b));
        }
    }
    if let Some(x) = num(d.get("panelH")).filter(|x| (100.0..=4000.0).contains(x)) {
        put("panelH", Value::Int(x as i64));
    }
    if let Some(Value::Int(n)) = d.get("v") {
        if (0..=100).contains(n) {
            put("v", Value::Int(*n));
        }
    }
    if let Some(Value::Obj(kv)) = d.get("colW") {
        let w: Vec<(String, Value)> = kv
            .iter()
            .take(40)
            .filter_map(|(k, v)| {
                let x = num(Some(v)).filter(|x| (20.0..=2000.0).contains(x))?;
                col_name(k).then(|| (k.clone(), Value::Int(x as i64)))
            })
            .collect();
        put("colW", Value::Obj(w));
    }
    if let Some(Value::Arr(a)) = d.get("cols") {
        let c: Vec<Value> = a
            .iter()
            .filter_map(Value::as_str)
            .filter(|s| col_name(s))
            .take(40)
            .map(Value::from)
            .collect();
        put("cols", Value::Arr(c));
    }
    if let Some(Value::Arr(a)) = d.get("focus") {
        put("focus", Value::Arr(clean_focus(a.iter().filter_map(Value::as_str))));
    }
    Value::Obj(out)
}

/// «Мои SSID»: без пустых, до 64 символов, не больше 20.
pub fn clean_focus<'a>(items: impl Iterator<Item = &'a str>) -> Vec<Value> {
    items
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .take(20)
        .map(|s| Value::from(s.chars().take(64).collect::<String>()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn keeps_only_known() {
        let v = parse(
            r#"{"theme":"dark\"><script>","density":"compact","connWin":300.0,"svOpacity":0.456,"auto":true,
            "panelH":350.7,"v":true,"colW":{"rssi":80,"BAD":90,"ssid":5},"cols":["ssid","x-y"],
            "focus":["  Office ","",3],"lang":"en","interval":7,"junk":1}"#,
        )
        .unwrap();
        assert_eq!(
            sanitize(&v).to_json(),
            r#"{"density":"compact","connWin":300.0,"svOpacity":0.46,"lang":"en","auto":true,"panelH":350,"colW":{"rssi":80},"cols":["ssid"],"focus":["Office"]}"#
        );
        assert_eq!(sanitize(&Value::Arr(vec![])).to_json(), "{}");
    }
}
