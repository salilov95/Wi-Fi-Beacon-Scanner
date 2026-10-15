//! Сверка ядра на Rust с эталонами Python-версии (`contract/golden`, см. `contract/README.ru.md`).
//!
//! На каждом снапшоте из `contract/fixtures` Rust собирает тот же документ, что `tools/golden.py`:
//! строки таблицы (`bss`, все поля, включая дерево IE и дополнения 802.11), проблемы (`findings`),
//! свободность каналов (`advice`) и загрузку (`util`) - на русском и английском - и сравнивает его с
//! эталоном целиком. Числа - с допуском 1e-6, как в `tools/golden.py`.

use std::fs;
use std::path::PathBuf;

use wbs_core::i18n::{with_lang, Lang};
use wbs_core::json::{self, Value};
use wbs_core::model::Snapshot;
use wbs_core::row::bss_row;
use wbs_core::rules::{analyze, channel_advice, channel_utilization, Thresholds};

const FLOAT_TOL: f64 = 1e-6;

fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contract")
}

fn fixtures() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(contract_dir().join("fixtures"))
        .expect("нет каталога contract/fixtures")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .map(|n| n.trim_end_matches(".json").to_string())
        .collect();
    names.sort();
    names
}

/// Отличия `got` от `want` (`want` - эталон). Пусто - совпадает.
fn differences(want: &Value, got: &Value, path: &str, out: &mut Vec<String>) {
    use Value::*;
    match (want, got) {
        (Int(_) | Num(_), Int(_) | Num(_)) => {
            let (a, b) = (want.as_f64().unwrap(), got.as_f64().unwrap());
            if (a - b).abs() > FLOAT_TOL {
                out.push(format!("{path}: {a} -> {b}"));
            }
        }
        (Arr(a), Arr(b)) => {
            if a.len() != b.len() {
                out.push(format!("{path}: длина {} -> {}", a.len(), b.len()));
            }
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                differences(x, y, &format!("{path}[{i}]"), out);
            }
        }
        (Obj(a), Obj(b)) => {
            for (k, x) in a {
                match got.get(k) {
                    Some(y) => differences(x, y, &format!("{path}/{k}"), out),
                    None => out.push(format!("{path}/{k}: пропало")),
                }
            }
            for (k, _) in b {
                if want.get(k).is_none() {
                    out.push(format!("{path}/{k}: лишнее поле"));
                }
            }
        }
        _ if want == got => {}
        _ => out.push(format!("{path}: {} -> {}", want.to_json(), got.to_json())),
    }
}

/// Документ эталона, собранный ядром на Rust (тот же формат, что `golden.compute` в Python).
fn compute(name: &str, lang: Lang, snap: &Snapshot) -> Value {
    with_lang(lang, || {
        let th = Thresholds::default();
        Value::Obj(vec![
            ("contract".into(), Value::Int(1)),
            ("fixture".into(), name.into()),
            ("lang".into(), lang.code().into()),
            ("bss".into(), Value::Arr(snap.bss.iter().map(bss_row).collect())),
            (
                "findings".into(),
                Value::Arr(analyze(&snap.bss, &th, &[]).iter().map(|f| f.to_value()).collect()),
            ),
            (
                "advice".into(),
                Value::Obj(
                    ["2.4", "5"]
                        .iter()
                        .map(|band| {
                            let rows = channel_advice(&snap.bss, band, 50.0);
                            (
                                band.to_string(),
                                Value::Arr(rows.iter().map(|r| r.to_value()).collect()),
                            )
                        })
                        .collect(),
                ),
            ),
            ("util".into(), channel_utilization(&snap.bss, None)),
        ])
    })
}

#[test]
fn full_golden_match() {
    let names = fixtures();
    assert!(names.len() >= 3, "мало снапшотов: {names:?}");
    let mut problems = vec![];
    let mut stats = (0, 0); // строк, проблем
    for name in &names {
        let text = fs::read_to_string(contract_dir().join(format!("fixtures/{name}.json"))).unwrap();
        let snap = Snapshot::from_json(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        for lang in [Lang::Ru, Lang::En] {
            let path = contract_dir().join(format!("golden/{name}.{}.json", lang.code()));
            let want = json::parse(&fs::read_to_string(&path).unwrap()).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            let got = compute(name, lang, &snap);
            differences(&want, &got, &format!("{name}.{}", lang.code()), &mut problems);
            stats.0 += snap.bss.len();
            stats.1 += want.get("findings").and_then(Value::as_array).map_or(0, |a| a.len());
        }
    }
    assert!(
        problems.is_empty(),
        "отличий от эталона: {}\n{}",
        problems.len(),
        problems[..problems.len().min(60)].join("\n")
    );
    println!(
        "проверено строк: {}, проблем: {}, снапшотов: {} x 2 языка",
        stats.0,
        stats.1,
        names.len()
    );
}

#[test]
fn golden_check_detects_damage() {
    // проверка проверки: испорченный документ должен давать отличия
    let name = &fixtures()[0];
    let text = fs::read_to_string(contract_dir().join(format!("fixtures/{name}.json"))).unwrap();
    let snap = Snapshot::from_json(&text).unwrap();
    let good = compute(name, Lang::Ru, &snap);
    let mut bad = good.clone();
    if let Value::Obj(kv) = &mut bad {
        for (k, v) in kv.iter_mut() {
            if k == "findings" {
                if let Value::Arr(a) = v {
                    a.pop();
                }
            }
            if k == "bss" {
                if let Value::Arr(a) = v {
                    if let Value::Obj(row) = &mut a[0] {
                        for (rk, rv) in row.iter_mut() {
                            if rk == "rssi" {
                                *rv = Value::Int(0);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut d = vec![];
    differences(&good, &bad, "", &mut d);
    assert_eq!(d.len(), 2, "{d:?}");
}
