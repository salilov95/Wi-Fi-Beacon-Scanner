//! Окно 2.x без Tauri - для разработки и проверки на любой ОС: интерфейс и `/api/*` по HTTP на 127.0.0.1.
//!
//!     cargo run --example devserver -- ../contract/fixtures/demo-office.json 8765
//!     (открыть http://127.0.0.1:8765/ в браузере)
//!
//! Данные - из снапшота (каждый «скан» возвращает его же). Сервер учебный: только для своей машины.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use wbs_core::app::{App, Config, FixtureBackend};
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("путь к снапшоту JSON");
    let port = args.get(2).map(|p| p.parse().expect("порт")).unwrap_or(8765u16);
    let snap = Snapshot::from_json(&std::fs::read_to_string(path).expect("чтение снапшота")).expect("снапшот");
    let cfg = Config {
        system_lang: wbs_core::i18n::Lang::parse(&std::env::var("WBS_LANG").unwrap_or_else(|_| "ru".into())),
        tz_offset_min: wbs_core::clock::env_offset_min(),
        ..Config::default()
    };
    let app = App::new(cfg, Box::new(FixtureBackend { snap }));
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("порт занят");
    eprintln!("http://127.0.0.1:{port}/");
    for s in listener.incoming().flatten() {
        let app = Arc::clone(&app);
        std::thread::spawn(move || {
            let _ = serve(app, s);
        });
    }
}
