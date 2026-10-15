//! Сверка ядра на Rust с эталонами Python-версии (`contract/golden`, см. `contract/README.ru.md`).
//!
//! На каждом снапшоте из `contract/fixtures` строка таблицы, которую считает Rust (`row::bss_row`), должна
//! совпасть с `bss[i]` эталона на обоих языках - по всем полям из `row::FIELDS`. Числа - с допуском 1e-6,
//! как в `tools/golden.py`. Поля, которых ещё нет в Rust (`std`, `ie_tree`), здесь не проверяются, но
//! тест падает, если в эталоне появилось поле, о котором Rust не знает вовсе.

use std::fs;
use std::path::PathBuf;

use wbs_core::json::{self, Value};
use wbs_core::model::Snapshot;
use wbs_core::row::{bss_row, FIELDS};

/// Поля эталона, которые Rust пока сознательно не считает (зависят от каталога переводов).
const NOT_YET: &[&str] = &["std", "ie_tree"];
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
        (Obj(a), Obj(_)) => {
            for (k, x) in a {
                match got.get(k) {
                    Some(y) => differences(x, y, &format!("{path}/{k}"), out),
                    None => out.push(format!("{path}/{k}: пропало")),
                }
            }
        }
        _ if want == got => {}
        _ => out.push(format!("{path}: {} -> {}", want.to_json(), got.to_json())),
    }
}

/// Только поля, которые считает Rust, - в порядке `FIELDS`.
fn pick(row: &Value) -> Value {
    Value::Obj(
        FIELDS
            .iter()
            .filter_map(|k| row.get(k).map(|v| (k.to_string(), v.clone())))
            .collect(),
    )
}

#[test]
fn rows_match_golden() {
    let names = fixtures();
    assert!(names.len() >= 3, "мало снапшотов: {names:?}");
    let mut problems = vec![];
    let mut checked = 0;
    for name in &names {
        let text = fs::read_to_string(contract_dir().join(format!("fixtures/{name}.json"))).unwrap();
        let snap = Snapshot::from_json(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        for lang in ["ru", "en"] {
            let path = contract_dir().join(format!("golden/{name}.{lang}.json"));
            let golden = json::parse(&fs::read_to_string(&path).unwrap()).unwrap_or_else(|e| panic!("{path:?}: {e}"));
            let rows = golden.get("bss").and_then(Value::as_array).expect("нет bss в эталоне");
            assert_eq!(rows.len(), snap.bss.len(), "{name}.{lang}: число BSS");
            for (i, (want, b)) in rows.iter().zip(&snap.bss).enumerate() {
                // в эталоне нет полей, о которых Rust не знает
                if let Value::Obj(kv) = want {
                    for (k, _) in kv {
                        assert!(
                            FIELDS.contains(&k.as_str()) || NOT_YET.contains(&k.as_str()),
                            "{name}.{lang}: новое поле эталона `{k}` - добавить в row.rs или в NOT_YET"
                        );
                    }
                }
                let mut d = vec![];
                differences(
                    &pick(want),
                    &bss_row(b),
                    &format!("{name}.{lang} bss[{i}] {}", b.bssid),
                    &mut d,
                );
                problems.extend(d);
                checked += 1;
            }
        }
    }
    assert!(
        problems.is_empty(),
        "отличий от эталона: {}\n{}",
        problems.len(),
        problems[..problems.len().min(60)].join("\n")
    );
    println!("проверено строк: {checked}, полей в строке: {}", FIELDS.len());
}

#[test]
fn golden_check_detects_damage() {
    // проверка проверки: испорченная строка должна давать отличия
    let name = &fixtures()[0];
    let text = fs::read_to_string(contract_dir().join(format!("fixtures/{name}.json"))).unwrap();
    let snap = Snapshot::from_json(&text).unwrap();
    let good = bss_row(&snap.bss[0]);
    let mut bad = good.clone();
    if let Value::Obj(kv) = &mut bad {
        for (k, v) in kv.iter_mut() {
            match k.as_str() {
                "rssi" => *v = Value::Int(0),
                "security" => *v = Value::Str("Open?".into()),
                "center" => *v = Value::Num(v.as_f64().unwrap() + 0.5),
                _ => {}
            }
        }
    }
    let mut d = vec![];
    differences(&good, &bad, "", &mut d);
    assert_eq!(d.len(), 3, "{d:?}");
    let mut same = vec![];
    differences(&good, &good, "", &mut same);
    assert!(same.is_empty());
}
