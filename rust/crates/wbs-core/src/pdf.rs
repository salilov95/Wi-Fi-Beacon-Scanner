//! PDF из HTML-отчёта через Edge/Chromium в режиме headless (печать в PDF). Перенос `wifi_beacon_scanner/pdf.py`.
//!
//! Отдельной PDF-библиотеки не нужно: Edge есть на любом Windows 10/11 и печатает ту же вёрстку, что HTML-отчёт.
//! Отдельный временный профиль - чтобы не мешать открытому Edge. Скриптов в отчёте нет, CSP их запрещает.
//! Как и в 1.x: ждём не выхода процесса, а готового файла (кончается на %%EOF и перестал расти), потом
//! закрываем дерево процессов; временная папка удаляется без ошибок, что не удалилось - позже в фоне.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::i18n::{tr, trf, Arg};

pub const ENV_BROWSER: &str = "WIFI_BEACON_SCANNER_PDF_BROWSER";

/// Где искать браузер: переменная окружения, Program Files, App Paths, PATH.
pub fn candidates() -> Vec<PathBuf> {
    let mut out = vec![];
    if let Some(p) = std::env::var_os(ENV_BROWSER) {
        out.push(PathBuf::from(p));
    }
    if cfg!(windows) {
        let bases: Vec<PathBuf> = ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
            .iter()
            .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
            .collect();
        for b in &bases {
            out.push(b.join("Microsoft").join("Edge").join("Application").join("msedge.exe"));
        }
        #[cfg(windows)]
        out.extend(crate::win::app_path("msedge.exe"));
        for b in &bases {
            out.push(b.join("Google").join("Chrome").join("Application").join("chrome.exe"));
        }
        #[cfg(windows)]
        out.extend(crate::win::app_path("chrome.exe"));
    }
    for name in ["msedge", "chromium", "chromium-browser", "google-chrome", "chrome"] {
        out.extend(which(name));
    }
    out
}

fn which(name: &str) -> Option<PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or(".EXE".into())
            .split(';')
            .map(str::to_lowercase)
            .collect()
    } else {
        vec![String::new()]
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .flat_map(|d| exts.iter().map(move |e| d.join(format!("{name}{e}"))))
        .find(|p| p.is_file())
}

pub fn find_browser() -> Option<PathBuf> {
    candidates().into_iter().find(|p| p.is_file())
}

fn pdf_ready(path: &Path) -> bool {
    let Ok(data) = std::fs::read(path) else { return false };
    data.len() >= 100 && data[data.len().saturating_sub(64)..].windows(5).any(|w| w == b"%%EOF")
}

/// `pathlib.Path.as_uri()`: file:///C:/... с процентным кодированием.
pub fn file_uri(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let mut out = String::from(if s.starts_with('/') { "file://" } else { "file:///" });
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

fn hide(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd
}

fn kill_tree(child: &mut std::process::Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if cfg!(windows) {
        let _ = hide(Command::new("taskkill").args(["/F", "/T", "/PID", &child.id().to_string()]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    } else {
        let _ = child.kill();
    }
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Удалить временную папку; если браузер ещё держит файлы - повторить в фоне.
fn rmtree_later(path: PathBuf) {
    let _ = std::fs::remove_dir_all(&path);
    if !path.exists() {
        return;
    }
    let _ = std::thread::Builder::new().name("pdf-cleanup".into()).spawn(move || {
        for _ in 0..6 {
            std::thread::sleep(Duration::from_secs(5));
            let _ = std::fs::remove_dir_all(&path);
            if !path.exists() {
                return;
            }
        }
    });
}

/// Печать HTML в PDF. Ошибка - понятным текстом (окно предложит открыть отчёт для печати вручную).
pub fn html_to_pdf(html: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let exe = find_browser().ok_or_else(|| tr("не найден Microsoft Edge (или Chrome) для печати в PDF"))?;
    let stamp = format!(
        "wbs_pdf_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let dir = std::env::temp_dir().join(stamp);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let res = print(&exe, &dir, html, timeout);
    rmtree_later(dir);
    res
}

fn print(exe: &Path, dir: &Path, html: &str, timeout: Duration) -> Result<Vec<u8>, String> {
    let src = dir.join("report.html");
    let out = dir.join("report.pdf");
    std::fs::write(&src, html).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(exe);
    if running_as_root() {
        cmd.arg("--no-sandbox"); // только Linux под root (контейнер с тестами)
    }
    cmd.args([
        "--headless",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-mode",
        "--disable-sync",
    ])
    .arg(format!("--user-data-dir={}", dir.join("profile").display()))
    .args(["--no-pdf-header-footer", "--print-to-pdf-no-header"])
    .arg(format!("--print-to-pdf={}", out.display()))
    .arg(file_uri(&src));
    let log = std::fs::File::create(dir.join("browser.log")).map_err(|e| e.to_string())?;
    let mut child = hide(&mut cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    let (mut last_size, mut stable_since): (Option<u64>, Option<Instant>) = (None, None);
    while t0.elapsed() < timeout {
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        if pdf_ready(&out) {
            let size = std::fs::metadata(&out).map(|m| m.len()).ok();
            if size == last_size {
                let since = *stable_since.get_or_insert_with(Instant::now);
                if exited || since.elapsed() >= Duration::from_millis(500) {
                    break;
                }
            } else {
                last_size = size;
                stable_since = None;
            }
        } else if exited {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    kill_tree(&mut child);
    if !pdf_ready(&out) {
        if t0.elapsed() >= timeout {
            return Err(trf(
                "браузер не успел напечатать PDF за %d с",
                &[Arg::I(timeout.as_secs() as i64)],
            ));
        }
        let code = child
            .try_wait()
            .ok()
            .flatten()
            .and_then(|s| s.code())
            .map_or("None".to_string(), |c| c.to_string());
        return Err(trf(
            "браузер не создал PDF (код выхода %s). Возможно, печать без окна запрещена политикой; открой отчёт для печати и сохрани в PDF через Ctrl+P",
            &[Arg::S(code)],
        ));
    }
    std::fs::read(&out).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri() {
        assert_eq!(
            file_uri(Path::new(r"C:\Users\Иван\Temp\a b.html")),
            "file:///C:/Users/%D0%98%D0%B2%D0%B0%D0%BD/Temp/a%20b.html"
        );
        assert_eq!(file_uri(Path::new("/tmp/x.html")), "file:///tmp/x.html");
    }
}
