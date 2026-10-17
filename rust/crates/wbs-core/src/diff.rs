//! Сравнение двух снапшотов: «до» (базовый) и «после» (текущий). Перенос `wifi_beacon_scanner/diff.py`.
//!
//! RSSI меняется всегда, поэтому он вынесен отдельно и показывается только при заметной разнице.

use std::collections::BTreeMap;

use crate::amend::{short, standards};
use crate::i18n::tr;
use crate::json::Value;
use crate::model::Bss;

fn pmf(b: &Bss) -> String {
    match &b.info.rsn {
        None => "-".into(),
        Some(r) if r.mfp_required => "required".into(),
        Some(r) if r.mfp_capable => "capable".into(),
        Some(_) => "no".into(),
    }
}

fn yn(v: bool) -> String {
    tr(if v { "да" } else { "нет" })
}

fn dash(s: String) -> String {
    if s.is_empty() {
        "-".into()
    } else {
        s
    }
}

type Field = (&'static str, fn(&Bss) -> String);

const FIELDS: &[Field] = &[
    ("SSID", |b| b.ssid_display()),
    ("Канал", |b| b.channel().to_string()),
    ("Ширина, МГц", |b| b.info.width_mhz().to_string()),
    ("Безопасность", |b| b.security()),
    ("Шифры", |b| dash(b.ciphers().join("/"))),
    ("PMF", pmf),
    ("802.11k", |b| yn(b.info.dot11k())),
    ("802.11r", |b| yn(b.info.dot11r())),
    ("802.11v", |b| yn(b.info.dot11v())),
    ("Дополнения 802.11", |b| dash(short(&standards(b)))),
    ("Поколение", |b| b.generation_label()),
    ("Страна", |b| dash(b.info.country.clone().unwrap_or_default())),
    ("Beacon interval", |b| b.beacon_interval.to_string()),
];

fn brief(b: &Bss) -> Value {
    Value::Obj(vec![
        ("bssid".into(), b.bssid.as_str().into()),
        ("ssid".into(), b.ssid_display().into()),
        ("band".into(), b.band().into()),
        ("channel".into(), b.channel().into()),
        ("rssi".into(), b.rssi.into()),
        ("security".into(), b.security().into()),
    ])
}

/// `{"added", "removed", "changed", "rssi", "rssi_delta", "same"}` - как `diff_snapshots` в 1.x.
pub fn diff_snapshots(old: &[Bss], new: &[Bss], rssi_delta: i32) -> Value {
    // dict в Python: при повторе BSSID остаётся последний
    let o: BTreeMap<&str, &Bss> = old.iter().map(|b| (b.bssid.as_str(), b)).collect();
    let n: BTreeMap<&str, &Bss> = new.iter().map(|b| (b.bssid.as_str(), b)).collect();
    let added: Vec<Value> = n
        .iter()
        .filter(|(k, _)| !o.contains_key(*k))
        .map(|(_, b)| brief(b))
        .collect();
    let removed: Vec<Value> = o
        .iter()
        .filter(|(k, _)| !n.contains_key(*k))
        .map(|(_, b)| brief(b))
        .collect();
    let mut changed = vec![];
    let mut rssi: Vec<(i32, Value)> = vec![];
    let mut common = 0usize;
    for (k, a) in &o {
        let Some(b) = n.get(k) else { continue };
        common += 1;
        let mut ch = vec![];
        for (name, f) in FIELDS {
            let (x, y) = (f(a), f(b));
            if x != y {
                ch.push(Value::Obj(vec![
                    ("field".into(), tr(name).into()),
                    ("old".into(), x.into()),
                    ("new".into(), y.into()),
                ]));
            }
        }
        if !ch.is_empty() {
            changed.push(Value::Obj(vec![
                ("bssid".into(), (*k).into()),
                ("ssid".into(), b.ssid_display().into()),
                ("changes".into(), Value::Arr(ch)),
            ]));
        }
        let d = b.rssi - a.rssi;
        if d.abs() >= rssi_delta {
            rssi.push((
                d,
                Value::Obj(vec![
                    ("bssid".into(), (*k).into()),
                    ("ssid".into(), b.ssid_display().into()),
                    ("old".into(), a.rssi.into()),
                    ("new".into(), b.rssi.into()),
                    ("delta".into(), d.into()),
                ]),
            ));
        }
    }
    rssi.sort_by_key(|r| r.0); // стабильно, как list.sort(key=delta)
    let same = common - changed.len();
    Value::Obj(vec![
        ("added".into(), Value::Arr(added)),
        ("removed".into(), Value::Arr(removed)),
        ("changed".into(), Value::Arr(changed)),
        ("rssi".into(), Value::Arr(rssi.into_iter().map(|r| r.1).collect())),
        ("rssi_delta".into(), rssi_delta.into()),
        ("same".into(), same.into()),
    ])
}
