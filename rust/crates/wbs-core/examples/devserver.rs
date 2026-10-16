//! Окно 2.x без Tauri - для разработки и проверки на любой ОС: интерфейс и `/api/*` по HTTP на 127.0.0.1.
//!
//!     cargo run --example devserver -- ../contract/fixtures/demo-office.json 8765
//!     (открыть http://127.0.0.1:8765/ в браузере)
//!
//! Данные - из снапшота (каждый «скан» возвращает его же). Сервер учебный: только для своей машины.
//! `WBS_BACKEND=windows` (только Windows) - настоящий скан, журнал Windows и проверка обновлений.
//! `WBS_JOURNAL=../contract/journal/scenarios/demo.json` - заполнить журнал подключения сценарием
//! (время сдвигается так, что сценарий кончается сейчас или в `WBS_JOURNAL_AT`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use wbs_core::app::{App, Config, ConnSink, FixtureBackend};
use wbs_core::json::Value;
use wbs_core::model::Snapshot;

fn serve(app: Arc<App>, stream: TcpStream) -> std::io::Result<()> {
    let mut r = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let (method, url) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("/").to_string(),
    );
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; len.min(16 * 1024 * 1024)];
    r.read_exact(&mut body)?;
    let reply = app.handle(&method, &url, &body);
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    )?;
    for (k, v) in reply.standard_headers() {
        write!(out, "{k}: {v}\r\n")?;
    }
    out.write_all(b"\r\n")?;
    out.write_all(&reply.body)?;
    if reply.quit {
        std::process::exit(0);
    }
    Ok(())
}

/// Сценарий журнала из contract/journal: все отметки времени сдвигаются к «сейчас».
fn replay(app: &App, path: &str) {
    let src = wbs_core::json::parse(&std::fs::read_to_string(path).expect("сценарий")).expect("JSON");
    let ops = src.get("ops").and_then(Value::as_array).expect("ops").clone();
    let last = ops
        .iter()
        .filter_map(|o| o.get("t").and_then(Value::as_f64))
        .fold(0.0, f64::max);
    // WBS_JOURNAL_AT=<unix-время>: сценарий кончается в это время (для сверки с 1.x), иначе - сейчас
    let end = std::env::var("WBS_JOURNAL_AT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or_else(wbs_core::clock::now_unix);
    let shift = end - last;
    let moved = |o: &Value| -> Value {
        let Value::Obj(kv) = o else { return o.clone() };
        Value::Obj(
            kv.iter()
                .map(|(k, v)| match (k.as_str(), v.as_f64()) {
                    ("t" | "lease", Some(x)) => (k.clone(), Value::Num(x + shift)),
                    _ => (k.clone(), v.clone()),
                })
                .collect(),
        )
    };
    app.with_conn(&mut |c| {
        for o in &ops {
            wbs_core::conn::replay_op(c, &moved(o)).expect("операция сценария");
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("путь к снапшоту JSON");
    let port = args.get(2).map(|p| p.parse().expect("порт")).unwrap_or(8765u16);
    let snap = Snapshot::from_json(&std::fs::read_to_string(path).expect("чтение снапшота")).expect("снапшот");
    #[allow(unused_mut)]
    let mut cfg = Config {
        system_lang: wbs_core::i18n::Lang::parse(&std::env::var("WBS_LANG").unwrap_or_else(|_| "ru".into())),
        tz_offset_min: wbs_core::clock::env_offset_min(),
        ..Config::default()
    };
    #[allow(unused_mut)]
    let mut backend: Box<dyn wbs_core::app::Backend> = Box::new(FixtureBackend { snap });
    // WBS_BACKEND=windows: настоящий источник Windows (скан, журнал Windows) и WinHTTP - для проверки в CI
    #[cfg(windows)]
    if std::env::var("WBS_BACKEND").as_deref() == Ok("windows") {
        backend = Box::new(wbs_core::win::WindowsBackend::new(None, 0));
        cfg.https_get = Some(wbs_core::win::https_get);
    }
    let app = App::new(cfg, backend);
    if let Ok(path) = std::env::var("WBS_JOURNAL") {
        replay(&app, &path);
    }
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("порт занят");
    eprintln!("http://127.0.0.1:{port}/");
    for s in listener.incoming().flatten() {
        let app = Arc::clone(&app);
        std::thread::spawn(move || {
            let _ = serve(app, s);
        });
    }
}
