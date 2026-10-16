//! Общее для тестов сверки с эталонами 1.x: где лежит контракт и сравнение документов JSON.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use wbs_core::json::Value;

pub const FLOAT_TOL: f64 = 1e-6;

pub fn contract_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contract")
}

pub fn fixtures() -> Vec<String> {
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
pub fn differences(want: &Value, got: &Value, path: &str, out: &mut Vec<String>) {
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
