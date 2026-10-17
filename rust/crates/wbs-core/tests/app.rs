//! `/api/*` без окна: маршруты, настройки, выгрузки, ошибки. Совпадение `/api/state` с 1.x по данным
//! проверяет `tools/compare_state.py` (Python-версия против `examples/devserver`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wbs_core::app::{App, Backend, Config, FixtureBackend, ScanError};
use wbs_core::i18n::Lang;
use wbs_core::json::{parse, Value};
use wbs_core::model::Snapshot;

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../../contract/fixtures/{name}.json"));
    std::fs::read_to_string(p).unwrap()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wbs-app-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn app_with(cfg: Config, backend: Box<dyn Backend>) -> Arc<App> {
    App::new(Config { test_mode: true, ..cfg }, backend)
}

fn app() -> Arc<App> {
    let snap = Snapshot::from_json(&fixture("demo-office")).unwrap();
    app_with(Config::default(), Box::new(FixtureBackend { snap }))
}

fn call(a: &Arc<App>, method: &str, url: &str, body: &str) -> (u16, Value) {
    let r = a.handle(method, url, body.as_bytes());
    let v = parse(std::str::from_utf8(&r.body).unwrap()).unwrap_or(Value::Null);
    (r.status, v)
}

fn wait_scan(a: &Arc<App>) -> Value {
    let t0 = Instant::now();
    loop {
        let (_, s) = call(a, "GET", "/api/state", "");
        if s.get("scanning") == Some(&Value::Bool(false)) {
            return s;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "скан не закончился");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Каждый адрес `/api/...`, который зовёт окно 1.x (app.js), должен иметь маршрут хотя бы для GET или POST.
/// «not found» - ответ на неизвестный маршрут; так нашёлся пропущенный `/api/conn/clear`.
#[test]
fn every_ui_route_exists() {
    let a = app();
    let js = String::from_utf8(a.handle("GET", "/app.js", b"").body).unwrap();
    let mut paths: Vec<String> = js
        .match_indices("/api/")
        .map(|(i, _)| {
            js[i..]
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || *c == '/' || *c == '_')
                .collect::<String>()
        })
        .map(|p| {
            if p == "/api/export/" {
                "/api/export/csv".to_string()
            } else {
                p
            }
        })
        .collect();
    paths.sort();
    paths.dedup();
    assert!(paths.len() >= 20, "{paths:?}");
    assert!(paths.iter().any(|p| p == "/api/conn/clear"));
    for p in &paths {
        let found = ["GET", "POST"].iter().any(|m| {
            let (_, v) = call(&a, m, p, "{}");
            v.get("error").and_then(Value::as_str) != Some("not found")
        });
        assert!(found, "окно зовёт {p}, а маршрута нет");
    }
}

#[test]
fn conn_clear() {
    let a = app();
    assert_eq!(
        call(&a, "POST", "/api/conn/clear", "{}"),
        (200, parse(r#"{"ok":true}"#).unwrap())
    );
}

#[test]
fn static_files_and_lang() {
    let a = app();
    let r = a.handle("GET", "/", b"");
    let html = String::from_utf8(r.body.clone()).unwrap();
    assert!(html.contains("<html lang=\"ru\">"), "{}", &html[..80]);
    assert_eq!(r.ctype, "text/html; charset=utf-8");
    assert!(r
        .standard_headers()
        .iter()
        .any(|(k, v)| *k == "Content-Security-Policy" && v.contains("script-src 'self'")));
    for p in ["/app.js", "/i18n.js", "/app.css"] {
        let r = a.handle("GET", p, b"");
        assert_eq!(r.status, 200, "{p}");
        assert!(r.body.len() > 1000, "{p}");
    }
    let (st, _) = call(&a, "POST", "/api/prefs", r#"{"lang":"en","theme":"dark"}"#);
    assert_eq!(st, 200);
    let html = String::from_utf8(a.handle("GET", "/", b"").body).unwrap();
    assert!(html.contains("<html lang=\"en\" data-theme=\"dark\">"));
    assert_eq!(call(&a, "GET", "/nope", "").0, 404);
}

#[test]
fn scan_history_and_exports() {
    let a = app();
    let (_, s) = call(&a, "GET", "/api/state", "");
    assert_eq!(s.get("taken_at"), Some(&Value::Null));
    assert_eq!(call(&a, "POST", "/api/export/csv", r#"{"scope":"all"}"#).0, 409);
    let (st, v) = call(&a, "POST", "/api/scan", r#"{"interface":0,"wait":4}"#);
    assert_eq!((st, v.get("started")), (202, Some(&Value::Bool(true))));
    let s = wait_scan(&a);
    call(&a, "POST", "/api/scan", "{}");
    let s2 = wait_scan(&a);
    assert_eq!(s.get("scan_count"), Some(&Value::Int(1)));
    assert_eq!(s2.get("scan_count"), Some(&Value::Int(2)));
    let bss = s2.get("bss").and_then(Value::as_array).unwrap();
    assert_eq!(bss.len(), 22);
    assert_eq!(bss[0].get("seen"), Some(&Value::Int(2)));
    assert_eq!(bss[0].get("seen_pct"), Some(&Value::Int(100)));
    // выгрузки
    let r = a.handle("POST", "/api/export/csv", br#"{"scope":"all"}"#);
    assert_eq!(r.status, 200);
    assert!(r.body.starts_with(&[0xEF, 0xBB, 0xBF, b's', b's', b'i', b'd']));
    assert!(r
        .headers
        .iter()
        .any(|(k, v)| *k == "Content-Disposition" && v.contains("wifi-bss.csv")));
    let r = a.handle("POST", "/api/export/history", br#"{"scope":"all"}"#);
    let text = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(text.lines().count(), 1 + 22 * 2, "{text}");
    let r = a.handle(
        "POST",
        "/api/export/json",
        br#"{"scope":"list","bssids":["00:00:00:00:00:00"]}"#,
    );
    assert_eq!(r.status, 400);
    let r = a.handle("GET", "/api/export/json", b"");
    let snap = Snapshot::from_json(std::str::from_utf8(&r.body).unwrap()).unwrap();
    assert_eq!(snap.bss.len(), 22);
    assert_eq!(call(&a, "POST", "/api/export/focus", r#"{"scope":"focus"}"#).0, 404);
    assert_eq!(call(&a, "POST", "/api/export/csv", r#"{"scope":"focus"}"#).0, 400);
    let r = a.handle("POST", "/api/export/html", br#"{"scope":"all"}"#);
    assert!(String::from_utf8(r.body).unwrap().starts_with("<!doctype html>"));
    let r = a.handle("POST", "/api/export/xlsx", br#"{"scope":"all"}"#);
    assert_eq!((r.status, &r.body[..2]), (200, &b"PK"[..]));
    // база для сравнения - текущий снапшот: diff нет, is_current
    assert_eq!(call(&a, "POST", "/api/baseline", r#"{"current":true}"#).0, 200);
    let (_, s) = call(&a, "GET", "/api/state", "");
    assert_eq!(s.get("diff"), Some(&Value::Null));
    assert_eq!(
        s.get("baseline").and_then(|b| b.get("is_current")),
        Some(&Value::Bool(true))
    );
    assert_eq!(call(&a, "POST", "/api/baseline", r#"{"clear":1}"#).0, 200);
    let (_, s) = call(&a, "GET", "/api/state", "");
    assert_eq!(s.get("baseline"), Some(&Value::Null));
}

/// Отчёт на английском: ни одной строки интерфейса по-русски (данные - SSID, причины Windows - тут латиницей).
/// Журнал и сессии - из сценария contract/journal/scenarios/demo.json, проигранного на английском.
#[test]
fn english_report_has_no_russian() {
    use wbs_core::app::ConnSink;
    let a = app();
    assert_eq!(call(&a, "POST", "/api/prefs", r#"{"lang":"en"}"#).0, 200);
    assert_eq!(call(&a, "POST", "/api/config", r#"{"focus":["CORP"]}"#).0, 200);
    assert_eq!(call(&a, "POST", "/api/scan", "{}").0, 202);
    wait_scan(&a);
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contract/journal/scenarios/demo.json");
    let text = std::fs::read_to_string(p).unwrap();
    let src = parse(&text).unwrap();
    let ops = src.get("ops").and_then(Value::as_array).unwrap().clone();
    wbs_core::i18n::with_lang(Lang::En, || {
        a.with_conn(&mut |c| {
            for o in &ops {
                wbs_core::conn::replay_op(c, o).unwrap();
            }
        })
    });
    for scope in ["all", "focus"] {
        let r = a.handle(
            "POST",
            "/api/export/html",
            format!(r#"{{"scope":"{scope}"}}"#).as_bytes(),
        );
        let html = String::from_utf8(r.body).unwrap();
        for section in [
            "id='problems'",
            "id='load'",
            "id='connection'",
            "id='sessions'",
            "id='bss'",
            "<svg",
        ] {
            assert!(html.contains(section), "{scope}: нет {section}");
        }
        let ru: Vec<&str> = html
            .split(['<', '>'])
            .filter(|t| t.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c)))
            // причины из самого сценария (так их пишет русская Windows) - данные, а не интерфейс
            .filter(|t| !text.contains(t.rsplit(": ").next().unwrap_or(t)))
            .collect();
        assert!(ru.is_empty(), "{scope}: русский текст в английском отчёте: {ru:?}");
    }
}

#[test]
fn config_and_prefs_files() {
    let dir = tmpdir("prefs");
    let legacy = dir.join("1x").join("prefs.json");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(
        &legacy,
        "\u{feff}{\"theme\":\"nord\",\"focus\":[\"CORP\"],\"lang\":\"en\",\"evil\":\"<script>\"}",
    )
    .unwrap();
    let own = dir.join("2x").join("prefs.json");
    let snap = Snapshot::from_json(&fixture("demo-office")).unwrap();
    let a = app_with(
        Config {
            prefs_path: Some(own.clone()),
            legacy_prefs_path: Some(legacy.clone()),
            ..Config::default()
        },
        Box::new(FixtureBackend { snap }),
    );
    assert_eq!(a.lang(), Lang::En);
    let (_, p) = call(&a, "GET", "/api/prefs", "");
    assert_eq!(p.to_json(), r#"{"theme":"nord","lang":"en","focus":["CORP"]}"#);
    let (_, s) = call(&a, "GET", "/api/state", "");
    assert_eq!(s.get("focus").unwrap().to_json(), r#"["CORP"]"#);
    // своих настроек ещё нет: файл 1.x не трогаем, свои появятся при первом сохранении
    assert!(!own.exists());
    assert_eq!(
        call(&a, "POST", "/api/config", r#"{"focus":"CORP"}"#).0,
        400,
        "focus должен быть списком"
    );
    call(&a, "POST", "/api/config", r#"{"focus":[" Home ",""],"weak_rssi":-70}"#);
    let saved = parse(&std::fs::read_to_string(&own).unwrap()).unwrap();
    assert_eq!(saved.get("focus").unwrap().to_json(), r#"["Home"]"#);
    // смена языка без lang в запросе язык не сбрасывает; focus через prefs не меняется
    call(&a, "POST", "/api/prefs", r#"{"theme":"light","focus":["X"]}"#);
    let saved = parse(&std::fs::read_to_string(&own).unwrap()).unwrap();
    assert_eq!(saved.to_json(), r#"{"theme":"light","focus":["Home"],"lang":"en"}"#);
    assert!(std::fs::read_to_string(&legacy).unwrap().contains("nord"));
    let _ = std::fs::remove_dir_all(&dir);
}

struct Denied;
impl Backend for Denied {
    fn name(&self) -> &str {
        "denied"
    }
    fn interfaces(&self) -> Result<Vec<String>, String> {
        Err(wbs_core::i18n::trf(
            "%s: код ошибки %d (%s)",
            &[
                wbs_core::i18n::Arg::S("WlanOpenHandle".into()),
                wbs_core::i18n::Arg::I(1062),
                wbs_core::i18n::Arg::S("-".into()),
            ],
        ))
    }
    fn scan(&self, _: usize, _: f64) -> Result<Snapshot, ScanError> {
        Err(ScanError::location())
    }
}

#[test]
fn scan_errors_and_misc_routes() {
    let a = app_with(
        Config {
            system_lang: Lang::En,
            ..Config::default()
        },
        Box::new(Denied),
    );
    let (_, s) = call(&a, "GET", "/api/state", "");
    assert_eq!(s.get("interfaces").unwrap().to_json(), "[]");
    // ошибка перечисления адаптеров при запуске - тоже на языке программы
    let ie = s.get("interfaces_error").and_then(Value::as_str).unwrap();
    assert!(ie.contains("error code 1062"), "{ie}");
    call(&a, "POST", "/api/scan", "{}");
    let s = wait_scan(&a);
    assert_eq!(s.get("error_kind"), Some(&Value::Str("location".into())));
    let err = s.get("error").and_then(Value::as_str).unwrap();
    assert!(
        err.starts_with("Windows denied the app access"),
        "перевод подсказки: {err}"
    );
    assert_eq!(call(&a, "POST", "/api/scan", "not json").0, 400);
    assert_eq!(call(&a, "POST", "/api/clientlog", "not json").0, 200);
    assert_eq!(call(&a, "POST", "/api/open", r#"{"target":"x"}"#).0, 400);
    let (st, v) = call(&a, "POST", "/api/open", r#"{"target":"logs"}"#);
    assert_eq!((st, v.get("ok")), (200, Some(&Value::Bool(false))));
    // журнал Windows: у источника без него - понятная ошибка и пустой список (как в 1.x)
    let (_, w) = call(&a, "GET", "/api/winlog?hours=24", "");
    assert_eq!(w.get("events").unwrap().to_json(), "[]");
    assert!(!w.get("error").and_then(Value::as_str).unwrap().is_empty());
    assert_eq!(w.get("hours"), None);
    let (_, u) = call(&a, "GET", "/api/update", "");
    assert!(u.get("error").and_then(Value::as_str).unwrap().contains("GitHub"));
    assert_eq!(
        u.get("current").and_then(Value::as_str),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(call(&a, "POST", "/api/load", r#"{"version":7}"#).0, 400);
    assert_eq!(call(&a, "POST", "/api/load", &fixture("synthetic-edge")).0, 200);
    let (_, s) = call(&a, "GET", "/api/state", "");
    assert_eq!(s.get("bss").and_then(Value::as_array).map(Vec::len), Some(15));
    assert_eq!(s.get("error"), Some(&Value::Null));
    let r = a.handle("POST", "/api/quit", b"{}");
    assert!(r.quit);
    assert_eq!(a.handle("PUT", "/api/state", b"").status, 405);
}
