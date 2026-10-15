//! Состояние программы и её HTTP-API для окна - перенос `web/state.py` (`AppState`) и маршрутов `web/server.py`.
//!
//! Окно 2.x показывает тот же интерфейс, что и 1.x (`wifi_beacon_scanner/web/static`), и ходит в те же `/api/*`.
//! Здесь нет сети и ОС: оболочка (Tauri или `examples/devserver.rs`) передаёт запрос в [`App::handle`]
//! и отдаёт ответ окну; скан делает [`Backend`] (на Windows - `scan_win`).
//!
//! Что ещё не перенесено (отвечает понятной ошибкой или пустыми данными в формате 1.x): журнал подключения
//! и сессии, журнал Windows, обход, HTML/PDF/Excel-отчёты, проверка обновлений.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::clock::{iso_with_offset, now_unix};
use crate::diff::diff_snapshots;
use crate::i18n::{tr, trf, with_lang, Arg, Lang};
use crate::ie::round1;
use crate::json::{self, Value};
use crate::model::Snapshot;
use crate::oui::OuiDb;
use crate::prefs::{clean_focus, sanitize, THEMES};
use crate::report::{render_csv, render_history_csv, snapshot_json};
use crate::row::bss_row;
use crate::rules::{analyze, channel_advice, channel_utilization, Finding, History, Thresholds};

/// Сколько последних замеров хранить на BSS.
pub const HISTORY_POINTS: usize = 240;
/// BSSID, которого не слышно дольше этого и нет в последних HISTORY_POINTS сканах, убирается из истории.
pub const HISTORY_TTL_S: f64 = 1800.0;
const MAX_BODY: usize = 12 * 1024 * 1024;
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
    img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
pub const REPO: &str = "https://github.com/salilov95/Wi-Fi-Beacon-Scanner";

/// Подсказка, когда Windows не дала доступ к скану (ключ перевода - как в 1.x).
pub const LOCATION_HINT: &str =
    "Windows не дала программе доступ к Wi-Fi-сканированию: с Windows 11 24H2 для этого нужно \
разрешение на расположение. Нажми «Да» в запросе Windows или включи «Параметры → \
Конфиденциальность и защита → Расположение → Разрешить классическим приложениям доступ к \
расположению». Скан повторится сам.";

const INDEX_HTML: &[u8] = include_bytes!("../../../../wifi_beacon_scanner/web/static/index.html");
const APP_JS: &[u8] = include_bytes!("../../../../wifi_beacon_scanner/web/static/app.js");
const I18N_JS: &[u8] = include_bytes!("../../../../wifi_beacon_scanner/web/static/i18n.js");
const APP_CSS: &[u8] = include_bytes!("../../../../wifi_beacon_scanner/web/static/app.css");

/// Текст, которого нет в каталоге 1.x (только в 2.x): сразу на двух языках.
pub fn pick(ru: &str, en: &str) -> String {
    match crate::i18n::get_lang() {
        Lang::Ru => ru.to_string(),
        Lang::En => en.to_string(),
    }
}

fn not_ported(what_ru: &str, what_en: &str) -> String {
    pick(
        &format!("{what_ru}: в 2.0 alpha ещё не перенесено, пока это есть в версии 1.x"),
        &format!("{what_en}: not ported to 2.0 alpha yet, use version 1.x for now"),
    )
}

// ---------------------------------------------------------------- источник данных

/// Ошибка скана; `kind = "location"` - нет разрешения на расположение (Windows 11 24H2+).
#[derive(Debug, Clone)]
pub struct ScanError {
    pub msg: String,
    pub kind: &'static str,
}

impl ScanError {
    pub fn new(msg: impl Into<String>) -> Self {
        ScanError {
            msg: msg.into(),
            kind: "",
        }
    }
    pub fn location() -> Self {
        ScanError {
            msg: String::new(),
            kind: "location",
        }
    }
}

/// Откуда берутся сканы: Windows (wlanapi), снапшот из файла, тесты.
pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn interfaces(&self) -> Result<Vec<String>, String>;
    fn scan(&self, interface_index: usize, wait_s: f64) -> Result<Snapshot, ScanError>;
}

/// Снапшот из файла: каждый «скан» возвращает его же со свежим временем (разработка и тесты).
pub struct FixtureBackend {
    pub snap: Snapshot,
}

impl Backend for FixtureBackend {
    fn name(&self) -> &str {
        "fixture"
    }
    fn interfaces(&self) -> Result<Vec<String>, String> {
        Ok(vec![self.snap.interface.clone()])
    }
    fn scan(&self, _: usize, _: f64) -> Result<Snapshot, ScanError> {
        Ok(self.snap.clone())
    }
}

// ---------------------------------------------------------------- настройки запуска

/// Открыть на компьютере URI или папку.
pub type OpenFn = fn(&str) -> Result<(), String>;

/// Что программе даёт оболочка: версия, пути, ОС.
pub struct Config {
    pub version: String,
    pub os: String,
    pub exe: String,
    /// Где хранить настройки вида.
    pub prefs_path: Option<PathBuf>,
    /// Настройки 1.x: читаются один раз, если своих ещё нет («Мои SSID», тема, язык).
    pub legacy_prefs_path: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
    pub log_dir: String,
    /// Язык, если его не выбрали в «Вид»: язык Windows.
    pub system_lang: Lang,
    /// Смещение местного пояса, минуты.
    pub tz_offset_min: i32,
    pub oui: Option<OuiDb>,
    /// Открыть на компьютере параметры Windows или папку (`/api/open`).
    pub open: Option<OpenFn>,
    /// Тесты: не писать журнал в stderr.
    pub test_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: env!("CARGO_PKG_VERSION").into(),
            os: std::env::consts::OS.into(),
            exe: String::new(),
            prefs_path: None,
            legacy_prefs_path: None,
            log_path: None,
            log_dir: String::new(),
            system_lang: Lang::Ru,
            tz_offset_min: 0,
            oui: None,
            open: None,
            test_mode: false,
        }
    }
}

// ---------------------------------------------------------------- ответ

/// Ответ окну. `quit` - оболочке пора закрыть программу (кнопка «Выход»).
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
    pub quit: bool,
}

impl Reply {
    fn new(status: u16, ctype: &'static str, body: Vec<u8>) -> Reply {
        Reply {
            status,
            ctype,
            body,
            headers: vec![],
            quit: false,
        }
    }
    pub fn json(status: u16, v: &Value) -> Reply {
        Reply::new(status, "application/json; charset=utf-8", v.to_json().into_bytes())
    }
    fn err(status: u16, msg: impl Into<String>) -> Reply {
        Reply::json(status, &obj(vec![("error", msg.into().into())]))
    }
    fn ok() -> Reply {
        Reply::json(200, &obj(vec![("ok", true.into())]))
    }
    fn file(data: Vec<u8>, ctype: &'static str, name: &str) -> Reply {
        let mut r = Reply::new(200, ctype, data);
        r.headers
            .push(("Content-Disposition", format!("attachment; filename=\"{name}\"")));
        r
    }
    /// Заголовки, которые 1.x отдаёт на каждый ответ.
    pub fn standard_headers(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("Content-Type", self.ctype.to_string()),
            ("Cache-Control", "no-store".into()),
            ("X-Content-Type-Options", "nosniff".into()),
            ("Content-Security-Policy", CSP.into()),
            ("Referrer-Policy", "no-referrer".into()),
        ];
        h.extend(self.headers.iter().cloned());
        h
    }
}

fn obj(kv: Vec<(&str, Value)>) -> Value {
    Value::Obj(kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Копия объекта с ключом `k` = `v` (как `dict(d, k=v)`: существующий ключ остаётся на своём месте).
fn with_key(d: &Value, k: &str, v: Value) -> Value {
    let mut kv = match d {
        Value::Obj(kv) => kv.clone(),
        _ => vec![],
    };
    match kv.iter_mut().find(|(key, _)| key == k) {
        Some(slot) => slot.1 = v,
        None => kv.push((k.to_string(), v)),
    }
    Value::Obj(kv)
}

// ---------------------------------------------------------------- состояние

struct Inner {
    lang: Lang,
    prefs: Value,
    snapshot: Option<Arc<Snapshot>>,
    findings: Vec<Finding>,
    history: History,
    scan_times: VecDeque<f64>,
    focus: Vec<String>,
    thresholds: Thresholds,
    scanning: bool,
    error: Option<String>,
    error_kind: &'static str,
    last_scan_ms: Option<u64>,
    last_scan_ok: bool,
    scan_count: u64,
    interfaces: Vec<String>,
    interfaces_error: Option<String>,
    baseline: Option<Arc<Snapshot>>,
    scan_args: (usize, f64),
}

pub struct App {
    pub cfg: Config,
    backend: Box<dyn Backend>,
    inner: Mutex<Inner>,
    log_lock: Mutex<()>,
    /// Окно уже спрашивало состояние (в журнал - один раз: так видно, что окно и протокол работают).
    connected: std::sync::atomic::AtomicBool,
}

impl App {
    pub fn new(cfg: Config, backend: Box<dyn Backend>) -> Arc<App> {
        let prefs = load_prefs(&cfg);
        let lang = prefs
            .get("lang")
            .and_then(Value::as_str)
            .map(Lang::parse)
            .unwrap_or(cfg.system_lang);
        let focus = prefs
            .get("focus")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let app = Arc::new(App {
            cfg,
            backend,
            inner: Mutex::new(Inner {
                lang,
                prefs,
                snapshot: None,
                findings: vec![],
                history: History::new(),
                scan_times: VecDeque::new(),
                focus,
                thresholds: Thresholds::default(),
                scanning: false,
                error: None,
                error_kind: "",
                last_scan_ms: None,
                last_scan_ok: true,
                scan_count: 0,
                interfaces: vec![],
                interfaces_error: None,
                baseline: None,
                scan_args: (0, 4.0),
            }),
            log_lock: Mutex::new(()),
            connected: std::sync::atomic::AtomicBool::new(false),
        });
        app.refresh_interfaces();
        app
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // если поток скана упал с паникой, данные остаются годными: лучше показать их, чем упасть всем окном
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn lang(&self) -> Lang {
        self.lock().lang
    }

    // ---- журнал программы ----

    /// Строка в журнал программы (`app.log`).
    pub fn log(&self, level: &str, msg: &str) {
        if self.cfg.log_path.is_none() && self.cfg.test_mode {
            return;
        }
        let _g = self.log_lock.lock().unwrap_or_else(|e| e.into_inner());
        log_line(self.cfg.log_path.as_deref(), self.cfg.tz_offset_min, level, msg);
    }

    // ---- интерфейсы и скан ----

    pub fn refresh_interfaces(&self) {
        let r = self.backend.interfaces();
        let mut st = self.lock();
        match r {
            Ok(v) => {
                st.interfaces = v;
                st.interfaces_error = None;
            }
            Err(e) => {
                st.interfaces = vec![];
                st.interfaces_error = Some(e);
            }
        }
    }

    /// Запускает скан в фоне; `false` - скан уже идёт.
    pub fn start_scan(self: &Arc<Self>, idx: usize, wait_s: f64) -> bool {
        {
            let mut st = self.lock();
            st.scan_args = (idx, wait_s);
            if st.scanning {
                return false;
            }
            st.scanning = true;
        }
        let app = Arc::clone(self);
        std::thread::spawn(move || {
            let lang = app.lang();
            with_lang(lang, || app.scan_worker(idx, wait_s));
        });
        true
    }

    fn scan_worker(&self, idx: usize, wait_s: f64) {
        let started = now_unix();
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.backend.scan(idx, wait_s)))
            .unwrap_or_else(|_| Err(ScanError::new(pick("скан упал (panic)", "scan crashed (panic)"))));
        let mut msgs: Vec<(&str, String)> = vec![];
        {
            let mut st = self.lock();
            match res {
                Ok(mut snap) => {
                    st.error = None;
                    st.error_kind = "";
                    st.last_scan_ms = Some(((now_unix() - started) * 1000.0).max(0.0) as u64);
                    let n = snap.bss.len();
                    if st.scan_count == 0 {
                        msgs.push((
                            "INFO",
                            format!(
                                "первый скан ({}): BSS {n} за {} мс",
                                snap.interface,
                                st.last_scan_ms.unwrap_or(0)
                            ),
                        ));
                    } else if !st.last_scan_ok && n > 0 {
                        msgs.push(("INFO", format!("скан снова работает: BSS {n}")));
                    }
                    if n == 0 {
                        msgs.push((
                            "WARNING",
                            format!(
                                "скан #{} вернул пустой список сетей ({})",
                                st.scan_count + 1,
                                snap.interface
                            ),
                        ));
                    }
                    st.last_scan_ok = n > 0;
                    if snap.taken_at.is_empty() || self.backend.name() == "fixture" {
                        snap.taken_at = iso_with_offset(now_unix(), self.cfg.tz_offset_min);
                    }
                    self.apply(&mut st, snap, Some(now_unix()));
                }
                Err(e) => {
                    let msg = if e.kind == "location" { tr(LOCATION_HINT) } else { e.msg };
                    if e.kind != "location" && (st.last_scan_ok || st.error.as_deref() != Some(msg.as_str())) {
                        msgs.push(("ERROR", format!("скан не удался: {msg}")));
                    }
                    st.last_scan_ok = false;
                    st.error = Some(msg);
                    st.error_kind = e.kind;
                }
            }
            st.scanning = false;
        }
        for (lvl, m) in msgs {
            self.log(lvl, &m);
        }
    }

    fn apply(&self, st: &mut Inner, mut snap: Snapshot, record_at: Option<f64>) {
        if let Some(db) = &self.cfg.oui {
            for b in &mut snap.bss {
                b.vendor = db.lookup(&b.bssid).map(String::from);
            }
        }
        st.findings = analyze(&snap.bss, &st.thresholds, &st.focus);
        if let Some(t) = record_at {
            for b in &snap.bss {
                let h = st.history.entry(b.bssid.clone()).or_default();
                if h.len() == HISTORY_POINTS {
                    h.pop_front();
                }
                h.push_back((t, b.rssi, b.info.qbss_util_pct));
            }
            st.scan_count += 1;
            if st.scan_times.len() == HISTORY_POINTS {
                st.scan_times.pop_front();
            }
            st.scan_times.push_back(t);
            if st.scan_times.len() >= HISTORY_POINTS {
                let cutoff = st.scan_times[0].min(t - HISTORY_TTL_S);
                st.history.retain(|_, h| h.back().is_some_and(|p| p.0 >= cutoff));
            }
        }
        st.snapshot = Some(Arc::new(snap));
    }

    fn reanalyze(st: &mut Inner) {
        if let Some(s) = st.snapshot.clone() {
            st.findings = analyze(&s.bss, &st.thresholds, &st.focus);
        }
    }

    pub fn load_snapshot(&self, snap: Snapshot) {
        let mut st = self.lock();
        st.history.clear();
        st.scan_times.clear();
        st.scan_count = 0;
        self.apply(&mut st, snap, Some(now_unix()));
        st.error = None;
    }

    // ---- настройки ----

    fn save_prefs(&self, prefs: &Value) {
        let Some(path) = &self.cfg.prefs_path else { return };
        let tmp = path.with_extension("json.tmp");
        let res = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|_| std::fs::write(&tmp, prefs.to_json()))
            .and_then(|_| std::fs::rename(&tmp, path));
        if let Err(e) = res {
            self.log("WARNING", &format!("настройки не сохранены: {e}"));
        }
    }

    fn set_prefs(&self, d: &Value) -> Value {
        let mut st = self.lock();
        let mut clean = sanitize(d);
        if let Value::Obj(kv) = &mut clean {
            kv.retain(|(k, _)| k != "focus"); // focus меняется только через /api/config
            for k in ["focus", "lang"] {
                // язык сбрасывается только явным выбором
                if !kv.iter().any(|(x, _)| x == k) {
                    if let Some(v) = st.prefs.get(k) {
                        kv.push((k.to_string(), v.clone()));
                    }
                }
            }
        }
        st.prefs = clean.clone();
        self.save_prefs(&clean);
        if let Some(l) = clean.get("lang").and_then(Value::as_str).map(Lang::parse) {
            if l != st.lang {
                st.lang = l;
                with_lang(l, || Self::reanalyze(&mut st));
            }
        }
        with_key(&st.prefs, "lang", st.lang.code().into())
    }

    fn set_config(&self, focus: Option<Vec<String>>, weak_rssi: Option<i32>) {
        let mut st = self.lock();
        if let Some(f) = focus {
            st.focus = f
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let clean = Value::Arr(clean_focus(st.focus.iter().map(String::as_str)));
            st.prefs = with_key(&st.prefs, "focus", clean);
            let p = st.prefs.clone();
            self.save_prefs(&p);
        }
        if let Some(w) = weak_rssi {
            st.thresholds.weak_rssi = w;
        }
        Self::reanalyze(&mut st);
    }

    // ---- состояние для окна ----

    pub fn state(&self) -> Value {
        let st = self.lock();
        let snap = st.snapshot.clone();
        let bss: &[crate::model::Bss] = snap.as_ref().map_or(&[], |s| &s.bss);
        let mut advice = vec![];
        if snap.is_some() {
            for band in ["2.4", "5"] {
                let rows = channel_advice(bss, band, 50.0);
                advice.push((band, Value::Arr(rows.iter().map(|r| r.to_value()).collect())));
            }
        }
        let denom = st.scan_count.clamp(1, HISTORY_POINTS as u64) as f64;
        let rows: Vec<Value> = bss
            .iter()
            .map(|b| {
                let mut row = bss_row(b);
                let extra: Vec<(&str, Value)> = match st.history.get(&b.bssid).filter(|h| !h.is_empty()) {
                    Some(h) => {
                        let vals: Vec<i32> = h.iter().map(|p| p.1).collect();
                        let n = h.len() as f64;
                        vec![
                            ("seen", h.len().into()),
                            (
                                "seen_pct",
                                Value::Int((100.0 * n / denom).round_ties_even().min(100.0) as i64),
                            ),
                            ("rssi_min", vals.iter().min().copied().into()),
                            ("rssi_max", vals.iter().max().copied().into()),
                            (
                                "rssi_avg",
                                round1(vals.iter().map(|&v| v as f64).sum::<f64>() / n).into(),
                            ),
                            ("first_seen", round1(h[0].0).into()),
                        ]
                    }
                    None => vec![
                        ("seen", 0.into()),
                        ("seen_pct", 0.into()),
                        ("rssi_min", b.rssi.into()),
                        ("rssi_max", b.rssi.into()),
                        ("rssi_avg", (b.rssi as f64).into()),
                        ("first_seen", Value::Null),
                    ],
                };
                if let Value::Obj(kv) = &mut row {
                    kv.extend(extra.into_iter().map(|(k, v)| (k.to_string(), v)));
                }
                row
            })
            .collect();
        let base = st.baseline.clone();
        let diff = match (&base, &snap) {
            (Some(b), Some(s)) if !Arc::ptr_eq(b, s) => diff_snapshots(&b.bss, &s.bss, 8),
            _ => Value::Null,
        };
        let baseline = base.as_ref().map_or(Value::Null, |b| {
            obj(vec![
                ("taken_at", b.taken_at.as_str().into()),
                ("count", b.bss.len().into()),
                ("is_current", snap.as_ref().is_some_and(|s| Arc::ptr_eq(b, s)).into()),
            ])
        });
        let history = Value::Obj(
            st.history
                .iter()
                .map(|(k, h)| {
                    (
                        k.clone(),
                        Value::Arr(
                            h.iter()
                                .map(|(t, r, u)| Value::Arr(vec![round1(*t).into(), (*r).into(), (*u).into()]))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        );
        obj(vec![
            ("scanning", st.scanning.into()),
            ("error", st.error.clone().into()),
            ("error_kind", st.error_kind.into()),
            ("lang", st.lang.code().into()),
            ("last_scan_ms", st.last_scan_ms.map(|m| Value::Int(m as i64)).into()),
            ("scan_count", Value::Int(st.scan_count as i64)),
            ("backend", self.backend.name().into()),
            ("interfaces", st.interfaces.clone().into()),
            ("interfaces_error", st.interfaces_error.clone().into()),
            ("focus", st.focus.clone().into()),
            ("weak_rssi", st.thresholds.weak_rssi.into()),
            ("taken_at", snap.as_ref().map(|s| s.taken_at.clone()).into()),
            (
                "adapter",
                snap.as_ref().map(|s| s.interface.clone()).unwrap_or_default().into(),
            ),
            ("bss", Value::Arr(rows)),
            ("baseline", baseline),
            ("diff", diff),
            (
                "findings",
                Value::Arr(st.findings.iter().map(|f| f.to_value()).collect()),
            ),
            (
                "advice",
                Value::Obj(advice.into_iter().map(|(k, v)| (k.to_string(), v)).collect()),
            ),
            (
                "util",
                if snap.is_some() {
                    channel_utilization(bss, Some(&st.history))
                } else {
                    obj(vec![("channels", Value::Arr(vec![])), ("no_data", Value::Arr(vec![]))])
                },
            ),
            ("conn", conn_stub()),
            ("sessions", sessions_stub()),
            ("survey", survey_stub()),
            ("history", history),
            ("now", round1(now_unix()).into()),
        ])
    }

    fn about(&self) -> Value {
        obj(vec![
            ("version", self.cfg.version.as_str().into()),
            ("backend", self.backend.name().into()),
            ("lang", self.lang().code().into()),
            ("python", "-".into()),
            ("os", self.cfg.os.as_str().into()),
            ("exe", self.cfg.exe.as_str().into()),
            ("frozen", true.into()),
            (
                "log",
                self.cfg
                    .log_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
                    .into(),
            ),
            ("log_dir", self.cfg.log_dir.as_str().into()),
            (
                "prefs",
                self.cfg
                    .prefs_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
                    .into(),
            ),
            ("repo", REPO.into()),
        ])
    }

    // ---- экспорт ----

    fn export(&self, fmt: &str, scope: &str, bssids: Option<&Value>) -> Reply {
        match fmt {
            "journal" | "sessions" => return Reply::err(501, not_ported("Журнал подключения", "Connection journal")),
            "html" | "pdf" | "xlsx" => {
                return Reply::err(
                    501,
                    not_ported("Отчёты HTML, PDF и Excel", "HTML, PDF and Excel reports"),
                )
            }
            "csv" | "json" | "history" => {}
            _ => return Reply::err(404, tr("неизвестный формат")),
        }
        let (snap, history) = {
            let st = self.lock();
            match &st.snapshot {
                None => return Reply::err(409, tr("ещё нет данных: сначала выполни скан")),
                Some(s) => ((**s).clone(), st.history.clone()),
            }
        };
        let focus = self.lock().focus.clone();
        let keep: Vec<crate::model::Bss> = match scope {
            "all" => snap.bss.clone(),
            "focus" => {
                if focus.is_empty() {
                    return Reply::err(
                        400,
                        tr("не заданы «Мои SSID»: впиши их в поле вверху или выбери «Все сети»"),
                    );
                }
                snap.bss.iter().filter(|b| focus.contains(&b.ssid())).cloned().collect()
            }
            "list" => {
                let list = match bssids {
                    Some(Value::Arr(a)) if a.len() <= 20000 && a.iter().all(|x| x.as_str().is_some()) => a,
                    _ => return Reply::err(400, tr("bssids должен быть списком строк")),
                };
                let wanted: std::collections::HashSet<String> =
                    list.iter().filter_map(Value::as_str).map(str::to_lowercase).collect();
                snap.bss.iter().filter(|b| wanted.contains(&b.bssid)).cloned().collect()
            }
            other => return Reply::err(400, trf("неизвестный scope: %r", &[Arg::S(other.into())])),
        };
        if keep.is_empty() {
            return Reply::err(400, tr("в выбранном наборе нет ни одной сети"));
        }
        let suffix = match scope {
            "focus" => "-my",
            "list" => "-filtered",
            _ => "",
        };
        let ids: std::collections::HashSet<&str> = keep.iter().map(|b| b.bssid.as_str()).collect();
        let hist: History = history.into_iter().filter(|(k, _)| ids.contains(k.as_str())).collect();
        let sub = Snapshot {
            taken_at: snap.taken_at.clone(),
            interface: snap.interface.clone(),
            bss: keep,
        };
        let mut bom = vec![0xEF, 0xBB, 0xBF]; // utf-8-sig: Excel сразу открывает кириллицу
        match fmt {
            "csv" => {
                bom.extend(render_csv(&sub.bss).into_bytes());
                Reply::file(bom, "text/csv; charset=utf-8", &format!("wifi-bss{suffix}.csv"))
            }
            "json" => Reply::file(
                snapshot_json(&sub).into_bytes(),
                "application/json",
                &format!("wifi-snapshot{suffix}.json"),
            ),
            _ => {
                if hist.is_empty() {
                    return Reply::err(409, tr("истории ещё нет: сделай хотя бы два скана"));
                }
                bom.extend(render_history_csv(&hist, &sub, self.cfg.tz_offset_min).into_bytes());
                Reply::file(bom, "text/csv; charset=utf-8", &format!("wifi-history{suffix}.csv"))
            }
        }
    }

    // ---- маршруты ----

    /// Один запрос окна: `GET`/`POST`, путь с query, тело.
    pub fn handle(self: &Arc<Self>, method: &str, url: &str, body: &[u8]) -> Reply {
        let lang = self.lang();
        with_lang(lang, || self.route(method, url, body))
    }

    fn route(self: &Arc<Self>, method: &str, url: &str, body: &[u8]) -> Reply {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        if method == "GET" {
            let _ = query; // /api/winlog?hours=... - журнал Windows ещё не перенесён
            return self.get(path);
        }
        if method != "POST" {
            return Reply::err(405, "method not allowed");
        }
        if body.len() > MAX_BODY {
            return Reply::err(400, tr("слишком большое тело запроса"));
        }
        let parsed = if body.is_empty() {
            Ok(Value::Obj(vec![]))
        } else {
            std::str::from_utf8(body)
                .map_err(|e| e.to_string())
                .and_then(json::parse)
        };
        let b = match parsed {
            Ok(v) => v,
            Err(_) if path == "/api/clientlog" || path == "/api/bye" => Value::Obj(vec![]),
            Err(e) => {
                return Reply::err(
                    400,
                    trf("неверный запрос (%s: %s)", &[Arg::S("ValueError".into()), Arg::S(e)]),
                )
            }
        };
        self.post(path, &b)
    }

    fn get(&self, path: &str) -> Reply {
        match path {
            "/" | "/index.html" => {
                let st = self.lock();
                let mut attrs = String::new();
                if let Some(t) = st.prefs.get("theme").and_then(Value::as_str) {
                    if t != "auto" && THEMES.contains(&t) {
                        attrs.push_str(&format!(" data-theme=\"{t}\""));
                    }
                }
                if let Some(d) = st.prefs.get("density").and_then(Value::as_str) {
                    if d == "normal" || d == "compact" {
                        attrs.push_str(&format!(" data-density=\"{d}\""));
                    }
                }
                let html = String::from_utf8_lossy(INDEX_HTML).replacen(
                    "<html lang=\"ru\">",
                    &format!("<html lang=\"{}\"{attrs}>", st.lang.code()),
                    1,
                );
                Reply::new(200, "text/html; charset=utf-8", html.into_bytes())
            }
            "/app.js" => Reply::new(200, "text/javascript; charset=utf-8", APP_JS.to_vec()),
            "/i18n.js" => Reply::new(200, "text/javascript; charset=utf-8", I18N_JS.to_vec()),
            "/app.css" => Reply::new(200, "text/css; charset=utf-8", APP_CSS.to_vec()),
            "/api/state" => {
                if !self.connected.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    self.log("INFO", "окно подключилось");
                }
                Reply::json(200, &self.state())
            }
            "/api/winlog" => Reply::json(
                200,
                &obj(vec![
                    ("events", Value::Arr(vec![])),
                    ("error", not_ported("Журнал Windows", "Windows event log").into()),
                ]),
            ),
            "/api/prefs" => {
                let st = self.lock();
                Reply::json(200, &with_key(&st.prefs, "lang", st.lang.code().into()))
            }
            "/api/about" => Reply::json(200, &self.about()),
            "/api/update" => Reply::json(
                200,
                &obj(vec![
                    ("current", self.cfg.version.as_str().into()),
                    ("latest", Value::Null),
                    ("newer", false.into()),
                    ("url", format!("{REPO}/releases").into()),
                    ("published", Value::Null),
                    ("error", not_ported("Проверка обновлений", "Update check").into()),
                ]),
            ),
            "/api/survey/plan" => Reply::err(404, tr("план не загружен")),
            "/api/survey/points" => Reply::json(
                200,
                &obj(vec![
                    ("rev", 0.into()),
                    ("name", tr("Обход").into()),
                    ("points", Value::Arr(vec![])),
                ]),
            ),
            "/api/survey/project" => Reply::err(409, tr("нечего сохранять: план не загружен")),
            p if p.starts_with("/api/export/") => self.export(&p["/api/export/".len()..], "all", None),
            _ => Reply::err(404, "not found"),
        }
    }

    fn post(self: &Arc<Self>, path: &str, b: &Value) -> Reply {
        match path {
            "/api/clientlog" => {
                let lvl = if b.get("level").and_then(Value::as_str) == Some("error") {
                    "ERROR"
                } else {
                    "WARNING"
                };
                let msg = match b.get("msg") {
                    Some(Value::Str(s)) => s.chars().take(4000).collect::<String>(),
                    Some(v) => v.to_json(),
                    None => String::new(),
                };
                self.log(lvl, &format!("page: {}", msg.replace(['\r', '\n'], " | ")));
                Reply::ok()
            }
            "/api/bye" => Reply::ok(), // окно 2.x - своё: его закрытие завершает программу само
            "/api/scan" => {
                let idx = b.get("interface").and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as usize;
                let wait = b.get("wait").and_then(Value::as_f64).unwrap_or(5.0).clamp(1.0, 30.0);
                let ok = self.start_scan(idx, wait);
                Reply::json(if ok { 202 } else { 409 }, &obj(vec![("started", ok.into())]))
            }
            "/api/config" => {
                let focus = match b.get("focus") {
                    None | Some(Value::Null) => None,
                    Some(Value::Arr(a)) if a.iter().all(|x| x.as_str().is_some()) => {
                        Some(a.iter().filter_map(Value::as_str).map(String::from).collect())
                    }
                    Some(_) => return Reply::err(400, tr("focus должен быть списком строк")),
                };
                let weak = b.get("weak_rssi").and_then(Value::as_f64).map(|x| x as i32);
                self.set_config(focus, weak);
                Reply::ok()
            }
            "/api/load" => match Snapshot::from_json(&b.to_json()) {
                Ok(s) => {
                    self.load_snapshot(s);
                    Reply::ok()
                }
                Err(e) => Reply::err(400, e),
            },
            p if p.starts_with("/api/export/") => self.export(
                &p["/api/export/".len()..],
                b.get("scope").and_then(Value::as_str).unwrap_or("all"),
                b.get("bssids"),
            ),
            "/api/prefs" => Reply::json(200, &self.set_prefs(b)),
            "/api/survey/plan" | "/api/survey/point" | "/api/survey/project" => {
                Reply::err(501, not_ported("Обход с планом этажа", "Floor-plan survey"))
            }
            "/api/survey/delete" | "/api/survey/clear" | "/api/conn/clear" => Reply::ok(),
            "/api/baseline" => {
                let truthy = |k: &str| !matches!(b.get(k), None | Some(Value::Null) | Some(Value::Bool(false)));
                let mut st = self.lock();
                if truthy("clear") {
                    st.baseline = None;
                } else if truthy("current") {
                    match st.snapshot.clone() {
                        Some(s) => st.baseline = Some(s),
                        None => return Reply::err(409, tr("ещё нет данных: сначала выполни скан")),
                    }
                } else {
                    match Snapshot::from_json(&b.to_json()) {
                        Ok(s) => st.baseline = Some(Arc::new(s)),
                        Err(e) => return Reply::err(400, e),
                    }
                }
                Reply::ok()
            }
            "/api/open" => {
                let target = b.get("target").and_then(Value::as_str).unwrap_or("");
                let uri = match target {
                    "location-settings" => "ms-settings:privacy-location".to_string(),
                    "logs" => self.cfg.log_dir.clone(),
                    _ => return Reply::err(400, tr("неизвестная цель")),
                };
                match self.cfg.open {
                    None => Reply::json(200, &obj(vec![("ok", false.into()), ("path", uri.into())])),
                    Some(open) => match open(&uri) {
                        Ok(()) => Reply::json(200, &obj(vec![("ok", true.into()), ("path", uri.into())])),
                        Err(e) => Reply::err(500, trf("не удалось открыть %s: %s", &[Arg::S(uri), Arg::S(e)])),
                    },
                }
            }
            "/api/quit" => {
                let mut r = Reply::ok();
                r.quit = true;
                r
            }
            _ => Reply::err(404, "not found"),
        }
    }
}

/// Строка в журнал: файл до 1 МБ, потом он переименовывается в `app.log.1`. Без файла - в stderr.
pub fn log_line(path: Option<&std::path::Path>, tz_offset_min: i32, level: &str, msg: &str) {
    let line = format!(
        "{} {level} {}\n",
        iso_with_offset(now_unix(), tz_offset_min),
        msg.replace(['\r', '\n'], " ")
    );
    let Some(path) = path else {
        eprint!("{line}");
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::metadata(path).map(|m| m.len() > 1_000_000).unwrap_or(false) {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

fn load_prefs(cfg: &Config) -> Value {
    let own = cfg.prefs_path.as_ref().filter(|p| p.exists());
    let path = own.or(cfg.legacy_prefs_path.as_ref().filter(|p| p.exists()));
    path.and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| json::parse(t.trim_start_matches('\u{feff}')).ok())
        .map(|v| sanitize(&v))
        .unwrap_or(Value::Obj(vec![]))
}

fn conn_stub() -> Value {
    obj(vec![
        ("status", not_ported("Журнал подключения", "Connection journal").into()),
        ("current", Value::Null),
        ("samples", Value::Arr(vec![])),
        ("events", Value::Arr(vec![])),
        (
            "stats",
            obj(vec![
                ("roams", 0.into()),
                ("disconnects", 0.into()),
                ("pingpong", 0.into()),
                ("sticky", 0.into()),
                ("attempt_fail", 0.into()),
                ("ssid_change", 0.into()),
                ("down_s", 0.0.into()),
                ("since", Value::Null),
                ("until", Value::Null),
                ("dwell", Value::Arr(vec![])),
            ]),
        ),
        ("raw", Value::Arr(vec![])),
    ])
}

fn sessions_stub() -> Value {
    let mut summary = vec![];
    for k in ["connects", "connects_ok", "connects_fail", "roams", "roams_fail"] {
        summary.push((k, Value::Int(0)));
    }
    for k in ["connect_ms_med", "roam_ms_med", "auth_ms_med", "ip_ms_med"] {
        summary.push((k, Value::Null));
    }
    summary.push(("onex_ok", 0.into()));
    summary.push(("onex_fail", 0.into()));
    obj(vec![("sessions", Value::Arr(vec![])), ("summary", obj(summary))])
}

fn survey_stub() -> Value {
    obj(vec![
        ("has_plan", false.into()),
        ("name", tr("Обход").into()),
        ("rev", 0.into()),
        ("plan_rev", 0.into()),
        ("points", 0.into()),
        ("pending", 0.into()),
    ])
}
