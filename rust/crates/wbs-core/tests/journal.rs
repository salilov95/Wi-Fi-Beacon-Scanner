//! Журнал подключения и сессии против 1.x: сценарии `contract/journal/scenarios` прогоняются через
//! `conn`/`session`, результат сравнивается с эталонами `contract/journal/golden` (их считает
//! `tools/journal_contract.py` на Python-версии): события, сводка, сессии, CSV, разбор 802.1X, оценка MCS.

mod common;

use std::fs;

use common::{contract_dir, differences};
use wbs_core::conn::{replay_op, ConnTracker};
use wbs_core::i18n::{with_lang, Lang};
use wbs_core::json::{self, Value};
use wbs_core::mcs::rate_to_mcs;
use wbs_core::onex::{parse_restart, parse_result_update};
use wbs_core::report::{render_journal_csv, render_sessions_csv};

fn run(ops: &[Value]) -> ConnTracker {
    let mut trk = ConnTracker::new();
    for o in ops {
        replay_op(&mut trk, o).unwrap();
    }
    trk
}

fn doc(ops: &[Value], lang: Lang) -> Value {
    with_lang(lang, || {
        let trk = run(ops);
        let events: Vec<_> = trk.events.iter().collect();
        let sessions: Vec<_> = trk.sessions.sessions.iter().collect();
        Value::Obj(vec![
            ("lang".into(), lang.code().into()),
            ("conn".into(), trk.to_value(3600, 500)),
            ("conn_small".into(), trk.to_value(5, 3)),
            ("sessions".into(), trk.sessions.to_value(200)),
            ("sessions_small".into(), trk.sessions.to_value(2)),
            ("journal_csv".into(), render_journal_csv(&events, 0).into()),
            ("sessions_csv".into(), render_sessions_csv(&sessions, 0).into()),
        ])
    })
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn extras(src: &Value, lang: Lang) -> Value {
    with_lang(lang, || {
        let onex = src.get("onex").unwrap();
        let hexes = |k: &str| -> Vec<Vec<u8>> {
            onex.get(k)
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .map(|h| unhex(h.as_str().unwrap()))
                .collect()
        };
        let mcs = src.get("mcs").and_then(Value::as_array).unwrap();
        Value::Obj(vec![
            ("lang".into(), lang.code().into()),
            (
                "onex_result".into(),
                Value::Arr(
                    hexes("result")
                        .iter()
                        .map(|b| parse_result_update(b).to_value())
                        .collect(),
                ),
            ),
            (
                "onex_restart".into(),
                Value::Arr(
                    hexes("restart")
                        .iter()
                        .map(|b| {
                            let (r, text) = parse_restart(b);
                            Value::Obj(vec![("reason".into(), r.into()), ("reason_ru".into(), text.into())])
                        })
                        .collect(),
                ),
            ),
            (
                "mcs".into(),
                Value::Arr(
                    mcs.iter()
                        .map(|c| {
                            let a = c.as_array().unwrap();
                            let n = a[4].as_i64().unwrap() as u32;
                            let found = rate_to_mcs(
                                a[0].as_f64(),
                                a[1].as_str().unwrap(),
                                a[2].as_i64().unwrap() as u32,
                                a[3].as_str().unwrap(),
                                3,
                                n,
                                n.min(2),
                            );
                            Value::Arr(found.iter().map(|g| g.to_value()).collect())
                        })
                        .collect(),
                ),
            ),
        ])
    })
}

#[test]
fn journal_matches_1x() {
    let dir = contract_dir().join("journal");
    let mut names: Vec<String> = fs::read_dir(dir.join("scenarios"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().trim_end_matches(".json").to_string())
        .collect();
    names.sort();
    assert!(names.len() >= 4, "{names:?}");
    let mut problems = vec![];
    let mut seen = (0, 0);
    for name in &names {
        let src = json::parse(&fs::read_to_string(dir.join(format!("scenarios/{name}.json"))).unwrap()).unwrap();
        for lang in [Lang::Ru, Lang::En] {
            let want =
                json::parse(&fs::read_to_string(dir.join(format!("golden/{name}.{}.json", lang.code()))).unwrap())
                    .unwrap();
            let got = if name == "extras" {
                extras(&src, lang)
            } else {
                let ops = src.get("ops").and_then(Value::as_array).unwrap();
                seen.0 += ops.len();
                let d = doc(ops, lang);
                seen.1 += d
                    .get("conn")
                    .and_then(|c| c.get("events"))
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                d
            };
            differences(&want, &got, &format!("{name}.{}", lang.code()), &mut problems);
        }
    }
    assert!(
        problems.is_empty(),
        "отличий от эталона: {}\n{}",
        problems.len(),
        problems[..problems.len().min(60)].join("\n")
    );
    println!(
        "журнал: сценариев {}, операций {}, событий {}",
        names.len(),
        seen.0,
        seen.1
    );
}
