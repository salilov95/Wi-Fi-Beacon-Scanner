//! Windows: скан через wlanapi.dll (Native Wifi API) и мелочи ОС. Перенос `scanner_win.py`.
//!
//! Как это работает (как и в 1.x):
//!  1. `WlanOpenHandle` - открыть сессию с WLAN-службой.
//!  2. `WlanEnumInterfaces` - список Wi-Fi адаптеров (у каждого свой GUID).
//!  3. `WlanScan` - попросить драйвер просканировать эфир. Вызов асинхронный: результаты появятся
//!     через несколько секунд.
//!  4. `WlanGetNetworkBssList` - забрать список BSS: на каждый BSS структура `WLAN_BSS_ENTRY`,
//!     сырые байты IE лежат по смещению `ulIeOffset` от начала этой структуры.
//!  5. `WlanFreeMemory` / `WlanCloseHandle`.
//!
//! Это НЕ monitor mode: видно то, что кэширует драйвер и служба.
//! Функции подключаются через `raw-dylib`: не нужны ни import-библиотеки SDK, ни крейт `windows`.

#![allow(clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::app::{log_line, Backend, ConnSink, MonitorHandle, ScanError};
use crate::clock::{iso_with_offset, now_unix};
use crate::i18n::{tr, trf, Arg, Lang};
use crate::model::{Bss, Snapshot};

pub(crate) type HANDLE = *mut c_void;

pub(crate) const ERROR_SUCCESS: u32 = 0;
pub(crate) const ERROR_ACCESS_DENIED: u32 = 5;
const DOT11_BSS_TYPE_ANY: u32 = 3;
/// Сколько ещё ждать, если после WlanScan список пуст (адаптер только проснулся).
const EMPTY_EXTRA_WAIT: Duration = Duration::from_secs(6);

#[allow(dead_code)]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct GUID {
    pub(crate) data1: u32,
    pub(crate) data2: u16,
    pub(crate) data3: u16,
    pub(crate) data4: [u8; 8],
}

#[allow(dead_code)]
#[repr(C)]
struct WlanInterfaceInfo {
    guid: GUID,
    description: [u16; 256],
    state: u32,
}

#[allow(dead_code)]
#[repr(C)]
pub(crate) struct Dot11Ssid {
    pub(crate) len: u32,
    pub(crate) ssid: [u8; 32],
}

#[allow(dead_code)]
#[repr(C)]
struct WlanRateSet {
    len: u32,
    rates: [u16; 126],
}

#[allow(dead_code)]
#[repr(C)]
struct WlanBssEntry {
    ssid: Dot11Ssid,
    phy_id: u32,
    bssid: [u8; 6],
    bss_type: u32,
    phy_type: u32,
    rssi: i32,
    link_quality: u32,
    in_reg_domain: u8,
    beacon_period: u16,
    timestamp: u64,
    host_timestamp: u64,
    capability: u16,
    center_freq_khz: u32,
    rate_set: WlanRateSet,
    ie_offset: u32,
    ie_size: u32,
}

// Размер из wlanapi.h - 360 байт; иначе раскладка не совпала с Windows и данные будут мусором.
const _: () = assert!(std::mem::size_of::<WlanBssEntry>() == 360);
const _: () = assert!(std::mem::size_of::<WlanInterfaceInfo>() == 532);

#[allow(dead_code)]
#[repr(C)]
struct SystemTime16([u16; 8]);

#[allow(dead_code)]
#[repr(C)]
struct TimeZoneInformation {
    bias: i32,
    standard_name: [u16; 32],
    standard_date: SystemTime16,
    standard_bias: i32,
    daylight_name: [u16; 32],
    daylight_date: SystemTime16,
    daylight_bias: i32,
}

#[allow(dead_code)]
#[repr(C)]
struct OsVersionInfoW {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd: [u16; 128],
}

#[cfg_attr(windows, link(name = "wlanapi", kind = "raw-dylib"))]
extern "system" {
    fn WlanOpenHandle(version: u32, reserved: *mut c_void, negotiated: *mut u32, handle: *mut HANDLE) -> u32;
    pub(crate) fn WlanCloseHandle(handle: HANDLE, reserved: *mut c_void) -> u32;
    fn WlanEnumInterfaces(handle: HANDLE, reserved: *mut c_void, list: *mut *mut c_void) -> u32;
    fn WlanScan(
        handle: HANDLE,
        guid: *const GUID,
        ssid: *const c_void,
        ie_data: *const c_void,
        reserved: *mut c_void,
    ) -> u32;
    fn WlanGetNetworkBssList(
        handle: HANDLE,
        guid: *const GUID,
        ssid: *const c_void,
        bss_type: u32,
        security_enabled: i32,
        reserved: *mut c_void,
        list: *mut *mut c_void,
    ) -> u32;
    pub(crate) fn WlanFreeMemory(memory: *mut c_void);
}

#[cfg_attr(windows, link(name = "kernel32", kind = "raw-dylib"))]
extern "system" {
    pub(crate) fn FormatMessageW(
        flags: u32,
        source: *const c_void,
        message_id: u32,
        language_id: u32,
        buffer: *mut u16,
        size: u32,
        args: *mut c_void,
    ) -> u32;
    fn GetTimeZoneInformation(tzi: *mut TimeZoneInformation) -> u32;
    fn GetUserDefaultUILanguage() -> u16;
}

#[cfg_attr(windows, link(name = "ntdll", kind = "raw-dylib"))]
extern "system" {
    fn RtlGetVersion(info: *mut OsVersionInfoW) -> i32;
}

/// Текст системной ошибки на языке Windows (`ctypes.FormatError`).
pub fn format_error(code: u32) -> String {
    let mut buf = [0u16; 512];
    // FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
    let n = unsafe {
        FormatMessageW(
            0x1000 | 0x200,
            std::ptr::null(),
            code,
            0,
            buf.as_mut_ptr(),
            buf.len() as u32,
            std::ptr::null_mut(),
        )
    };
    String::from_utf16_lossy(&buf[..n as usize]).trim().to_string()
}

pub(crate) fn check(code: u32, what: &str) -> Result<(), String> {
    if code == ERROR_SUCCESS {
        return Ok(());
    }
    Err(trf(
        "%s: код ошибки %d (%s)",
        &[Arg::S(what.into()), Arg::I(code as i64), Arg::S(format_error(code))],
    ))
}

/// Сессия WLAN: закрывается сама.
pub(crate) struct Session(pub(crate) HANDLE);

impl Session {
    pub(crate) fn open() -> Result<Session, String> {
        let mut ver = 0u32;
        let mut h: HANDLE = std::ptr::null_mut();
        check(
            unsafe { WlanOpenHandle(2, std::ptr::null_mut(), &mut ver, &mut h) },
            "WlanOpenHandle",
        )?;
        Ok(Session(h))
    }

    pub(crate) fn interfaces(&self) -> Result<Vec<(String, GUID)>, String> {
        let mut p: *mut c_void = std::ptr::null_mut();
        check(
            unsafe { WlanEnumInterfaces(self.0, std::ptr::null_mut(), &mut p) },
            "WlanEnumInterfaces",
        )?;
        let mut out = vec![];
        unsafe {
            let count = *(p as *const u32); // dwNumberOfItems, затем dwIndex
            let first = (p as *const u8).add(8) as *const WlanInterfaceInfo;
            for i in 0..count as usize {
                let info = &*first.add(i);
                let end = info.description.iter().position(|&c| c == 0).unwrap_or(256);
                out.push((String::from_utf16_lossy(&info.description[..end]), info.guid));
            }
            WlanFreeMemory(p);
        }
        Ok(out)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            WlanCloseHandle(self.0, std::ptr::null_mut());
        }
    }
}

pub(crate) fn mac(b: &[u8; 6]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

/// Разбирает WLAN_BSS_LIST и освобождает его.
unsafe fn read_bss_list(p: *mut c_void) -> Vec<Bss> {
    let n = *((p as *const u8).add(4) as *const u32); // после dwTotalSize
    let first = (p as *const u8).add(8);
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let addr = first.add(i * std::mem::size_of::<WlanBssEntry>());
        let e = &*(addr as *const WlanBssEntry);
        let ie = if e.ie_size > 0 {
            std::slice::from_raw_parts(addr.add(e.ie_offset as usize), e.ie_size as usize).to_vec()
        } else {
            vec![]
        };
        let len = (e.ssid.len as usize).min(32);
        out.push(Bss::new(
            &mac(&e.bssid),
            e.ssid.ssid[..len].to_vec(),
            e.rssi,
            e.link_quality,
            e.center_freq_khz,
            e.beacon_period as u32,
            e.capability,
            e.phy_type,
            ie,
        ));
    }
    WlanFreeMemory(p);
    out
}

/// Источник данных 1.x `WindowsBackend`: скан через wlanapi.
pub struct WindowsBackend {
    pub log_path: Option<PathBuf>,
    pub tz_offset_min: i32,
    last_scan_rc: AtomicU32,
}

impl WindowsBackend {
    pub fn new(log_path: Option<PathBuf>, tz_offset_min: i32) -> Self {
        WindowsBackend {
            log_path,
            tz_offset_min,
            last_scan_rc: AtomicU32::new(ERROR_SUCCESS),
        }
    }
    fn log(&self, level: &str, msg: &str) {
        log_line(self.log_path.as_deref(), self.tz_offset_min, level, msg);
    }
}

impl Backend for WindowsBackend {
    fn name(&self) -> &str {
        "windows"
    }

    fn start_conn_monitor(
        &self,
        sink: std::sync::Arc<dyn ConnSink>,
        interface_index: usize,
    ) -> Result<Option<Box<dyn MonitorHandle>>, String> {
        crate::win_conn::start(sink, interface_index).map(Some)
    }

    fn read_winlog(&self, hours: f64) -> Result<Vec<crate::json::Value>, String> {
        crate::win_log::read_events(hours, 2000)
    }

    fn interfaces(&self) -> Result<Vec<String>, String> {
        Ok(Session::open()?.interfaces()?.into_iter().map(|(d, _)| d).collect())
    }

    fn scan(&self, interface_index: usize, wait_s: f64) -> Result<Snapshot, ScanError> {
        let s = Session::open().map_err(ScanError::new)?;
        let ifaces = s.interfaces().map_err(ScanError::new)?;
        if ifaces.is_empty() {
            return Err(ScanError::new(tr("Wi-Fi адаптеры не найдены")));
        }
        let Some((desc, guid)) = ifaces.get(interface_index) else {
            return Err(ScanError::new(trf(
                "Нет адаптера с индексом %d (всего %d)",
                &[Arg::I(interface_index as i64), Arg::I(ifaces.len() as i64)],
            )));
        };
        // Код != 0 не фатален (служба может отклонить слишком частый запрос - тогда читаем кэш).
        // Код 5 - Windows 11 24H2+ не дала доступ к расположению: при первом вызове она сама спрашивает.
        let rc = unsafe { WlanScan(s.0, guid, std::ptr::null(), std::ptr::null(), std::ptr::null_mut()) };
        if self.last_scan_rc.swap(rc, Ordering::Relaxed) != rc {
            if rc != ERROR_SUCCESS {
                self.log(
                    "WARNING",
                    &format!("WlanScan вернул {rc} ({}), читаю кэш", format_error(rc)),
                );
            } else {
                self.log("INFO", "WlanScan снова работает");
            }
        }
        std::thread::sleep(Duration::from_secs_f64(wait_s));
        let deadline = Instant::now() + EMPTY_EXTRA_WAIT;
        loop {
            let mut p: *mut c_void = std::ptr::null_mut();
            let rc = unsafe {
                WlanGetNetworkBssList(
                    s.0,
                    guid,
                    std::ptr::null(),
                    DOT11_BSS_TYPE_ANY,
                    0,
                    std::ptr::null_mut(),
                    &mut p,
                )
            };
            if rc == ERROR_ACCESS_DENIED {
                self.log(
                    "WARNING",
                    "WlanGetNetworkBssList: доступ запрещён (5) - нет разрешения на расположение",
                );
                return Err(ScanError::location());
            }
            check(rc, "WlanGetNetworkBssList").map_err(ScanError::new)?;
            let bss = unsafe { read_bss_list(p) };
            if !bss.is_empty() || Instant::now() >= deadline {
                return Ok(Snapshot {
                    taken_at: iso_with_offset(now_unix(), self.tz_offset_min),
                    interface: desc.clone(),
                    bss,
                });
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// Смещение местного пояса от UTC, минуты (с учётом летнего времени).
pub fn local_offset_min() -> i32 {
    let mut tzi = TimeZoneInformation {
        bias: 0,
        standard_name: [0; 32],
        standard_date: SystemTime16([0; 8]),
        standard_bias: 0,
        daylight_name: [0; 32],
        daylight_date: SystemTime16([0; 8]),
        daylight_bias: 0,
    };
    let id = unsafe { GetTimeZoneInformation(&mut tzi) };
    let extra = match id {
        1 => tzi.standard_bias,
        2 => tzi.daylight_bias,
        _ => 0,
    };
    if id == u32::MAX {
        return 0;
    }
    -(tzi.bias + extra)
}

/// `Windows 10.0.26100` - как `platform.system() platform.version()` в 1.x.
pub fn os_name() -> String {
    let mut v = OsVersionInfoW {
        size: std::mem::size_of::<OsVersionInfoW>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        csd: [0; 128],
    };
    if unsafe { RtlGetVersion(&mut v) } != 0 {
        return "Windows".into();
    }
    format!("Windows {}.{}.{}", v.major, v.minor, v.build)
}

/// Язык интерфейса Windows: русский или английский (как `system_lang` в 1.x).
pub fn system_lang() -> Lang {
    if unsafe { GetUserDefaultUILanguage() } & 0x3FF == 0x19 {
        Lang::Ru
    } else {
        Lang::En
    }
}

/// Открыть параметры Windows (`ms-settings:...`) или папку - через Проводник, без окна консоли.
pub fn open_target(uri: &str) -> Result<(), String> {
    std::process::Command::new("explorer.exe")
        .arg(uri)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- HTTPS (проверка обновлений)

#[cfg_attr(windows, link(name = "winhttp", kind = "raw-dylib"))]
extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> HANDLE;
    fn WinHttpSetTimeouts(h: HANDLE, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
    fn WinHttpConnect(session: HANDLE, server: *const u16, port: u16, reserved: u32) -> HANDLE;
    fn WinHttpOpenRequest(
        connect: HANDLE,
        verb: *const u16,
        object: *const u16,
        version: *const u16,
        referrer: *const u16,
        accept: *const *const u16,
        flags: u32,
    ) -> HANDLE;
    fn WinHttpSendRequest(
        req: HANDLE,
        headers: *const u16,
        headers_len: u32,
        optional: *mut c_void,
        optional_len: u32,
        total_len: u32,
        context: usize,
    ) -> i32;
    fn WinHttpReceiveResponse(req: HANDLE, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(
        req: HANDLE,
        level: u32,
        name: *const u16,
        buffer: *mut c_void,
        len: *mut u32,
        index: *mut u32,
    ) -> i32;
    fn WinHttpReadData(req: HANDLE, buffer: *mut c_void, to_read: u32, read: *mut u32) -> i32;
    fn WinHttpCloseHandle(h: HANDLE) -> i32;
}

#[cfg_attr(windows, link(name = "kernel32", kind = "raw-dylib"))]
extern "system" {
    #[link_name = "GetLastError"]
    fn get_last_error() -> u32;
}

/// Закрывается сама.
struct Http(HANDLE);

impl Drop for Http {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn http_err(what: &str) -> String {
    let code = unsafe { get_last_error() };
    let text = format_error(code);
    if text.is_empty() {
        format!("{what}: WinHTTP {code}")
    } else {
        format!("{what}: {text} ({code})")
    }
}

/// GET по HTTPS через WinHTTP: системный прокси, таймауты 6 с (как urllib в 1.x). Тело ответа или ошибка.
pub fn https_get(host: &str, path: &str) -> Result<String, String> {
    let agent = wide("WiFiBeaconScanner");
    // 4 = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY (Windows 8.1+), 0 - прокси из настроек WinHTTP
    let mut s = Http(unsafe { WinHttpOpen(agent.as_ptr(), 4, std::ptr::null(), std::ptr::null(), 0) });
    if s.0.is_null() {
        s = Http(unsafe { WinHttpOpen(agent.as_ptr(), 0, std::ptr::null(), std::ptr::null(), 0) });
    }
    if s.0.is_null() {
        return Err(http_err("WinHttpOpen"));
    }
    unsafe { WinHttpSetTimeouts(s.0, 6000, 6000, 6000, 6000) };
    let h = wide(host);
    let c = Http(unsafe { WinHttpConnect(s.0, h.as_ptr(), 443, 0) });
    if c.0.is_null() {
        return Err(http_err("WinHttpConnect"));
    }
    let (verb, obj) = (wide("GET"), wide(path));
    // 0x00800000 = WINHTTP_FLAG_SECURE
    let r = Http(unsafe {
        WinHttpOpenRequest(
            c.0,
            verb.as_ptr(),
            obj.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0x0080_0000,
        )
    });
    if r.0.is_null() {
        return Err(http_err("WinHttpOpenRequest"));
    }
    let headers = wide("Accept: application/vnd.github+json\r\n");
    let ok = unsafe { WinHttpSendRequest(r.0, headers.as_ptr(), u32::MAX, std::ptr::null_mut(), 0, 0, 0) };
    if ok == 0 || unsafe { WinHttpReceiveResponse(r.0, std::ptr::null_mut()) } == 0 {
        return Err(http_err("HTTPS"));
    }
    let (mut status, mut len) = (0u32, 4u32);
    // 19 = WINHTTP_QUERY_STATUS_CODE, 0x20000000 = WINHTTP_QUERY_FLAG_NUMBER
    unsafe {
        WinHttpQueryHeaders(
            r.0,
            19 | 0x2000_0000,
            std::ptr::null(),
            &mut status as *mut u32 as *mut c_void,
            &mut len,
            std::ptr::null_mut(),
        )
    };
    let mut body = vec![];
    let mut buf = [0u8; 8192];
    loop {
        let mut n = 0u32;
        if unsafe { WinHttpReadData(r.0, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut n) } == 0 {
            return Err(http_err("WinHttpReadData"));
        }
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n as usize]);
        if body.len() > 4 << 20 {
            return Err("ответ больше 4 МБ".into());
        }
    }
    if !(200..300).contains(&status) {
        return Err(format!("HTTP Error {status}"));
    }
    String::from_utf8(body).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- реестр: App Paths (где Windows находит msedge.exe)

#[cfg_attr(windows, link(name = "advapi32", kind = "raw-dylib"))]
extern "system" {
    fn RegGetValueW(
        hkey: HANDLE,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        size: *mut u32,
    ) -> i32;
}

/// Путь из `HKLM/HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\<exe>`, если файл есть.
pub fn app_path(exe: &str) -> Option<std::path::PathBuf> {
    let key = wide(&format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}"));
    for hive in [0x8000_0002usize, 0x8000_0001usize] {
        let mut buf = [0u16; 1024];
        let mut size = (buf.len() * 2) as u32;
        // 0x2 = RRF_RT_REG_SZ; значение по умолчанию - имя null
        let rc = unsafe {
            RegGetValueW(
                hive as HANDLE,
                key.as_ptr(),
                std::ptr::null(),
                0x2,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
            )
        };
        if rc != 0 {
            continue;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let p = String::from_utf16_lossy(&buf[..n]).trim().trim_matches('"').to_string();
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}
