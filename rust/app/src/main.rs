//! Wi-Fi Beacon Scanner 2.x: окно на Tauri 2.
//!
//! Окно открывает `http://wbs.localhost/` (на macOS/Linux - `wbs://localhost/`): это не сеть, а свой
//! протокол `wbs`, запросы к нему Tauri отдаёт этой программе. Интерфейс тот же, что у 1.x
//! (`wifi_beacon_scanner/web/static`), `/api/*` отвечает `wbs_core::app::App` - так у окна нет ни порта,
//! ни локального сервера, а логика и данные совпадают с 1.x (проверяется в `wbs-core`).
//!
//! Рядом с 1.x: свой идентификатор, папка установки, настройки (`%APPDATA%\WiFiBeaconScanner2`)
//! и журнал (`%LOCALAPPDATA%\WiFiBeaconScanner2\logs\app.log`). Настройки 1.x читаются один раз,
//! пока своих нет («Мои SSID», тема, язык).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Arc;

use tauri::http::Response;
use tauri::{WebviewUrl, WebviewWindowBuilder};
use wbs_core::app::{log_line, App, Backend, Config};
use wbs_core::oui::OuiDb;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_DIR: &str = "WiFiBeaconScanner2";
/// Папка настроек 1.x - только для чтения при первом запуске.
const APP_DIR_1X: &str = "WiFiBeaconScanner";
/// manuf из Wireshark, зашитый при сборке (build.rs, WBS_MANUF); пустой, если его не было.
const MANUF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/manuf"));

fn env_dir(var: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Командная строка (как у 1.x `gui`): `--demo [снапшот.json]`, `--ssid SSID` (можно несколько раз),
/// `--manuf путь`, `--lang ru|en`. Остальное игнорируется.
#[derive(Default)]
struct Args {
    demo: Option<Option<PathBuf>>,
    ssid: Vec<String>,
    manuf: Option<PathBuf>,
    lang: Option<wbs_core::i18n::Lang>,
}

fn parse_args() -> Args {
    let mut a = Args::default();
    // `--ssid=CORP` - как `--ssid CORP` (argparse в 1.x понимает обе записи)
    let argv: Vec<String> = std::env::args()
        .skip(1)
        .flat_map(|s| match s.split_once('=') {
            Some((k, v)) if k.starts_with("--") => vec![k.to_string(), v.to_string()],
            _ => vec![s],
        })
        .collect();
    let mut i = 0;
    while i < argv.len() {
        let next = argv.get(i + 1).filter(|v| !v.starts_with("--")).cloned();
        match argv[i].as_str() {
            "--demo" => {
                // `--demo=` - пустой путь, как и `--demo` без файла: демо-скан из программы
                a.demo = Some(next.clone().filter(|v| !v.is_empty()).map(PathBuf::from));
                i += next.is_some() as usize;
            }
            "--ssid" | "--manuf" | "--lang" if next.is_some() => {
                let v = next.unwrap_or_default();
                match argv[i].as_str() {
                    "--ssid" => a.ssid.push(v),
                    "--manuf" => a.manuf = Some(PathBuf::from(v)),
                    _ => a.lang = Some(wbs_core::i18n::Lang::parse(&v)),
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    a
}

fn load_oui() -> Option<OuiDb> {
    let embedded = String::from_utf8_lossy(MANUF);
    if !embedded.trim().is_empty() {
        return Some(OuiDb::parse(&embedded));
    }
    for p in [
        r"C:\Program Files\Wireshark\manuf",
        r"C:\Program Files (x86)\Helge Keck\WinFi\vendors.txt",
    ] {
        if let Ok(b) = std::fs::read(p) {
            return Some(OuiDb::parse(&String::from_utf8_lossy(&b)));
        }
    }
    None
}

#[cfg(windows)]
fn platform(log_path: Option<PathBuf>, tz: i32) -> (Box<dyn Backend>, String, wbs_core::i18n::Lang) {
    use wbs_core::win;
    (
        Box::new(win::WindowsBackend::new(log_path, tz)),
        win::os_name(),
        win::system_lang(),
    )
}

#[cfg(not(windows))]
fn platform(_: Option<PathBuf>, _: i32) -> (Box<dyn Backend>, String, wbs_core::i18n::Lang) {
    // Скан на macOS и Linux - следующие этапы; пока окно показывает демо-снапшот.
    let snap = wbs_core::model::Snapshot::from_json(include_str!("../../../contract/fixtures/demo-office.json"))
        .expect("демо-снапшот");
    (
        Box::new(wbs_core::app::FixtureBackend { snap }),
        std::env::consts::OS.to_string(),
        wbs_core::i18n::Lang::En,
    )
}

fn build_core(args: &Args) -> Result<Arc<App>, String> {
    let roaming = env_dir("APPDATA");
    let local = env_dir("LOCALAPPDATA");
    let log_dir = local.join(APP_DIR).join("logs");
    let log_path = log_dir.join("app.log");
    #[cfg(windows)]
    let tz = wbs_core::win::local_offset_min();
    #[cfg(not(windows))]
    let tz = wbs_core::clock::env_offset_min();

    let lp = log_path.clone();
    std::panic::set_hook(Box::new(move |info| {
        log_line(Some(&lp), tz, "ERROR", &format!("panic: {info}"));
    }));

    let (mut backend, os, system_lang) = platform(Some(log_path.clone()), tz);
    if let Some(demo) = &args.demo {
        // демо-режим без сканирования; можно указать свой снапшот
        let base = match demo {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
                Some(wbs_core::model::Snapshot::from_json(&text)?)
            }
            None => None,
        };
        backend = Box::new(wbs_core::demo::DemoBackend::new(base, tz));
    }
    let oui = match &args.manuf {
        Some(p) => std::fs::read(p)
            .ok()
            .map(|b| OuiDb::parse(&String::from_utf8_lossy(&b))),
        None => load_oui(),
    };
    let cfg = Config {
        version: VERSION.into(),
        os,
        exe: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        prefs_path: Some(roaming.join(APP_DIR).join("prefs.json")),
        legacy_prefs_path: Some(roaming.join(APP_DIR_1X).join("prefs.json")),
        log_path: Some(log_path),
        log_dir: log_dir.display().to_string(),
        system_lang,
        tz_offset_min: tz,
        oui,
        #[cfg(windows)]
        open: Some(wbs_core::win::open_target),
        #[cfg(not(windows))]
        open: None,
        #[cfg(windows)]
        https_get: Some(wbs_core::win::https_get),
        #[cfg(not(windows))]
        https_get: None,
        focus: args.ssid.clone(),
        lang: args.lang,
        test_mode: false,
    };
    let vendors = cfg.oui.as_ref().map_or(0, |d| d.len());
    let os_line = cfg.os.clone();
    let core = App::new(cfg, backend);
    core.log(
        "INFO",
        &format!("запуск {VERSION} (Rust + Tauri), {os_line}, вендоров в базе {vendors}"),
    );
    Ok(core)
}

fn main() {
    let args = parse_args();
    let core = match build_core(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    core.start_scan(0, 4.0); // первый скан идёт, пока открывается окно
    core.start_monitors(); // журнал подключения: опрос и уведомления Windows в своём потоке
    let for_protocol = Arc::clone(&core);
    let result = tauri::Builder::default()
        .register_asynchronous_uri_scheme_protocol("wbs", move |ctx, request, responder| {
            let core = Arc::clone(&for_protocol);
            let handle = ctx.app_handle().clone();
            // запрос обрабатывается вне главного потока: окно не замирает, пока считается /api/state
            std::thread::spawn(move || {
                let url = request
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| "/".into());
                let reply = core.handle(request.method().as_str(), &url, request.body());
                let mut b = Response::builder().status(reply.status);
                for (k, v) in reply.standard_headers() {
                    b = b.header(k, v);
                }
                let quit = reply.quit;
                match b.body(reply.body) {
                    Ok(resp) => responder.respond(resp),
                    Err(e) => core.log("ERROR", &format!("ответ окну не собран: {e}")),
                }
                if quit {
                    core.log("INFO", "выход по кнопке «Выход»");
                    handle.exit(0);
                }
            });
        })
        .setup(|app| {
            let url = if cfg!(windows) {
                "http://wbs.localhost/"
            } else {
                "wbs://localhost/"
            };
            WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url.parse().expect("url")))
                .title(format!("Wi-Fi Beacon Scanner {VERSION}"))
                .inner_size(1440.0, 900.0)
                .min_inner_size(900.0, 560.0)
                // ссылки наружу (страница релиза на GitHub) - в браузере по умолчанию, как из окна Edge в 1.x;
                // окно для печати отчёта (about:blank, blob:) открывается внутри программы
                .on_new_window(|url, _features| {
                    let external = matches!(url.scheme(), "http" | "https") && url.host_str() != Some("wbs.localhost");
                    if external {
                        #[cfg(windows)]
                        let _ = wbs_core::win::open_target(url.as_str());
                        return tauri::webview::NewWindowResponse::Deny;
                    }
                    tauri::webview::NewWindowResponse::Allow
                })
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!());
    if let Err(e) = result {
        core.log("ERROR", &format!("окно не запустилось: {e}"));
    }
}
