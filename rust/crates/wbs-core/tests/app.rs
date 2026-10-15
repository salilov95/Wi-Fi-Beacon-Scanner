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
    assert_eq!(call(&a, "POST", "/api/export/pdf", r#"{"scope":"all"}"#).0, 501);
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
    let (_, w) = call(&a, "GET", "/api/winlog?hours=24", "");
    assert!(w.get("error").and_then(Value::as_str).unwrap().contains("not ported"));
    let (_, u) = call(&a, "GET", "/api/update", "");
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
