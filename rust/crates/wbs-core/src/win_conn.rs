//! Монитор подключения ноутбука на Windows. Перенос `conn_win.py` и `ip_win.py`.
//!
//! Источники:
//!  1. опрос раз в секунду: `WlanQueryInterface` (current_connection, rssi, channel_number) - роуминги и обрывы;
//!  2. уведомления `WlanRegisterNotification` ACM/MSM - коды причин и стадии подключения для сессий
//!     (если Windows не даёт MSM или 802.1X - подписываемся на то, что разрешено);
//!  3. уведомления 802.1X (ONEX) - результат EAP, причина, тип EAP, чья учётка;
//!  4. IPv4 и аренда DHCP адаптера (`GetAdaptersInfo`), пока подключение свежее.
//!
//! Callback уведомлений вызывает служба WLAN в своём потоке: в нём только копирование в очередь,
//! вся обработка - в потоке монитора под замком состояния программы (`ConnSink`).

use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::{ConnSink, MonitorHandle};
use crate::clock::now_unix;
use crate::conn::{ConnSample, ConnTracker};
use crate::i18n::{tr, trf, with_lang, Arg};
use crate::onex::{parse_restart, parse_result_update, ONEX_AUTH_RESTARTED, ONEX_RESULT_UPDATE};
use crate::win::{format_error, mac, Dot11Ssid, Session, WlanFreeMemory, ERROR_ACCESS_DENIED, GUID, HANDLE};

const OP_INTERFACE_STATE: u32 = 6;
const OP_CURRENT_CONNECTION: u32 = 7;
const OP_CHANNEL_NUMBER: u32 = 8;
const OP_RSSI: u32 = 0x1000_0102;

const SRC_ONEX: u32 = 0x04;
const SRC_ACM: u32 = 0x08;
const SRC_MSM: u32 = 0x10;

const ACM_CONNECTION_COMPLETE: u32 = 10;
const ACM_ATTEMPT_FAIL: u32 = 11;
const ACM_DISCONNECTED: u32 = 21;

fn acm_name(off: u32) -> Option<&'static str> {
    Some(match off {
        7 => "scan_complete",
        8 => "scan_fail",
        9 => "connection_start",
        10 => "connection_complete",
        11 => "connection_attempt_fail",
        18 => "network_not_available",
        19 => "network_available",
        20 => "disconnecting",
        21 => "disconnected",
        _ => return None,
    })
}

fn msm_name(off: u32) -> Option<&'static str> {
    Some(match off {
        1 => "associating",
        2 => "associated",
        3 => "authenticating",
        4 => "connected",
        5 => "roaming_start",
        6 => "roaming_end",
        7 => "radio_state_change",
        8 => "signal_quality_change",
        9 => "disassociating",
        10 => "disconnected",
        15 => "link_degraded",
        16 => "link_improved",
        _ => return None,
    })
}

/// ACM / MSM -> стадии машины состояний (session.rs).
fn acm_stage(off: u32) -> Option<&'static str> {
    Some(match off {
        9 => "start",
        10 => "complete",
        11 => "fail",
        21 => "disconnected",
        _ => return None,
    })
}

fn msm_stage(off: u32) -> Option<&'static str> {
    Some(match off {
        1 => "associating",
        2 => "associated",
        3 => "authenticating",
        4 => "connected",
        5 => "roam_start",
        6 => "roam_end",
        9 => "disassociating",
        10 => "disconnected",
        _ => return None,
    })
}

fn if_state(v: u32) -> Option<&'static str> {
    Some(match v {
        0 => "not_ready",
        1 => "connected",
        2 => "ad_hoc",
        3 => "disconnecting",
        4 => "disconnected",
        5 => "associating",
        6 => "discovering",
        7 => "authenticating",
        _ => return None,
    })
}

/// DOT11_AUTH_ALGORITHM: подписаны только значения, в которых уверены (как в 1.x).
fn auth_name(v: u32) -> String {
    match v {
        1 => "Open".into(),
        2 => "Shared key".into(),
        3 => "WPA".into(),
        4 => "WPA-PSK".into(),
        5 => "WPA-None".into(),
        6 => "WPA2 (RSNA)".into(),
        7 => "WPA2-PSK".into(),
        _ => format!("auth {v}"),
    }
}

fn cipher_name(v: u32) -> String {
    match v {
        0 => "нет".into(),
        1 => "WEP-40".into(),
        2 => "TKIP".into(),
        4 => "CCMP".into(),
        5 => "WEP-104".into(),
        0x100 => "use group".into(),
        0x101 => "WEP".into(),
        _ => format!("cipher {v}"),
    }
}

// ---------------------------------------------------------------- структуры wlanapi.h, iphlpapi.h

#[allow(dead_code)]
#[repr(C)]
struct WlanAssociationAttributes {
    ssid: Dot11Ssid,
    bss_type: u32,
    bssid: [u8; 6],
    phy_type: u32,
    phy_index: u32,
    signal_quality: u32,
    rx_rate: u32,
    tx_rate: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct WlanSecurityAttributes {
    security_enabled: i32,
    onex_enabled: i32,
    auth_algorithm: u32,
    cipher_algorithm: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct WlanConnectionAttributes {
    state: u32,
    mode: u32,
    profile: [u16; 256],
    assoc: WlanAssociationAttributes,
    security: WlanSecurityAttributes,
}

#[allow(dead_code)]
#[repr(C)]
struct WlanNotificationData {
    source: u32,
    code: u32,
    guid: GUID,
    data_size: u32,
    data: *mut c_void,
}

#[allow(dead_code)]
#[repr(C)]
struct WlanConnectionNotificationData {
    mode: u32,
    profile: [u16; 256],
    ssid: Dot11Ssid,
    bss_type: u32,
    security_enabled: i32,
    reason: u32,
    flags: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct WlanMsmNotificationData {
    mode: u32,
    profile: [u16; 256],
    ssid: Dot11Ssid,
    bss_type: u32,
    mac: [u8; 6],
    security_enabled: i32,
    first_peer: i32,
    last_peer: i32,
    reason: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct IpAddrString {
    next: *mut IpAddrString,
    ip: [u8; 16],
    mask: [u8; 16],
    context: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct IpAdapterInfo {
    next: *mut IpAdapterInfo,
    combo_index: u32,
    adapter_name: [u8; 260],
    description: [u8; 132],
    address_length: u32,
    address: [u8; 8],
    index: u32,
    kind: u32,
    dhcp_enabled: u32,
    current_ip: *mut c_void,
    ip_list: IpAddrString,
    gateway_list: IpAddrString,
    dhcp_server: IpAddrString,
    have_wins: i32,
    primary_wins: IpAddrString,
    secondary_wins: IpAddrString,
    lease_obtained: i64,
    lease_expires: i64,
}

// Размеры для Windows x64 - как в winstructs.py / ip_win.py 1.x
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(std::mem::size_of::<WlanConnectionAttributes>() == 604);
    assert!(std::mem::size_of::<WlanNotificationData>() == 40);
    assert!(std::mem::size_of::<WlanConnectionNotificationData>() == 568);
    assert!(std::mem::size_of::<WlanMsmNotificationData>() == 580);
    assert!(std::mem::size_of::<IpAdapterInfo>() == 704);
};

type NotifyCb = extern "system" fn(*const WlanNotificationData, *mut c_void);

#[cfg_attr(windows, link(name = "wlanapi", kind = "raw-dylib"))]
extern "system" {
    fn WlanQueryInterface(
        handle: HANDLE,
        guid: *const GUID,
        opcode: u32,
        reserved: *mut c_void,
        size: *mut u32,
        data: *mut *mut c_void,
        value_type: *mut u32,
    ) -> u32;
    fn WlanRegisterNotification(
        handle: HANDLE,
        source: u32,
        ignore_duplicate: i32,
        callback: Option<NotifyCb>,
        context: *mut c_void,
        reserved: *mut c_void,
        prev: *mut u32,
    ) -> u32;
    fn WlanReasonCodeToString(code: u32, size: u32, buffer: *mut u16, reserved: *mut c_void) -> u32;
}

#[cfg_attr(windows, link(name = "iphlpapi", kind = "raw-dylib"))]
extern "system" {
    fn GetAdaptersInfo(info: *mut IpAdapterInfo, size: *mut u32) -> u32;
}

/// Текст причины WLAN (`WlanReasonCodeToString`), на языке Windows.
pub fn reason_text(code: u32) -> String {
    if code == 0 {
        return String::new();
    }
    let mut buf = [0u16; 512];
    let rc = unsafe { WlanReasonCodeToString(code, buf.len() as u32, buf.as_mut_ptr(), std::ptr::null_mut()) };
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if rc == 0 && n > 0 {
        return String::from_utf16_lossy(&buf[..n]);
    }
    trf("код причины 0x%X", &[Arg::I(code as i64)])
}

/// Текст системной ошибки, в том числе EAP HRESULT, если он есть в таблицах Windows.
pub fn win_error_text(code: u32) -> String {
    if code == 0 {
        return String::new();
    }
    let t = format_error(code);
    if t.is_empty() {
        trf("ошибка 0x%08X", &[Arg::I(code as i64)])
    } else {
        t
    }
}

fn ssid_str(s: &Dot11Ssid) -> String {
    let n = (s.len as usize).min(32);
    String::from_utf8_lossy(&s.ssid[..n]).into_owned()
}

fn u16_str(a: &[u16]) -> String {
    let n = a.iter().position(|&c| c == 0).unwrap_or(a.len());
    String::from_utf16_lossy(&a[..n])
}

fn cstr(a: &[u8]) -> String {
    let n = a.iter().position(|&c| c == 0).unwrap_or(a.len());
    String::from_utf8_lossy(&a[..n]).trim().to_string()
}

/// GUID из WLAN API в виде `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (так его называет GetAdaptersInfo).
fn guid_str(g: &GUID) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02X}")).collect::<String>();
    format!(
        "{{{:08X}-{:04X}-{:04X}-{}-{}}}",
        g.data1,
        g.data2,
        g.data3,
        hex(&g.data4[..2]),
        hex(&g.data4[2..])
    )
}

/// IPv4, DHCP-сервер и аренда адаптера: (ip, dhcp, сервер, аренда получена).
fn adapter_ip(guid: &str) -> Option<(String, bool, String, Option<f64>)> {
    let mut size = 0u32;
    unsafe { GetAdaptersInfo(std::ptr::null_mut(), &mut size) };
    if size == 0 {
        return None;
    }
    // буфер с выравниванием по 8: в структуре указатели и i64
    let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut IpAdapterInfo;
    if unsafe { GetAdaptersInfo(p, &mut size) } != 0 {
        return None;
    }
    let want = guid.to_uppercase();
    let mut cur = p as *const IpAdapterInfo;
    while !cur.is_null() {
        let a = unsafe { &*cur };
        if cstr(&a.adapter_name).to_uppercase() == want {
            let dhcp = a.dhcp_enabled != 0;
            return Some((
                cstr(&a.ip_list.ip),
                dhcp,
                if dhcp { cstr(&a.dhcp_server.ip) } else { String::new() },
                (dhcp && a.lease_obtained > 0).then_some(a.lease_obtained as f64),
            ));
        }
        cur = a.next;
    }
    None
}

// ---------------------------------------------------------------- очередь уведомлений

struct Item {
    t: f64,
    src: u32,
    code: u32,
    off: u32,
    ssid: String,
    mac: String,
    reason: u32,
    raw: Vec<u8>,
}

/// Очередь из callback службы WLAN в поток монитора (монитор в программе один).
static QUEUE: Mutex<VecDeque<Item>> = Mutex::new(VecDeque::new());

extern "system" fn on_notification(p: *const WlanNotificationData, _ctx: *mut c_void) {
    // паника в callback службы недопустима: всё под catch_unwind
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let d = unsafe { &*p };
        let off = d.code & 0x0FFF;
        let size = d.data_size as usize;
        let mut item = Item {
            t: now_unix(),
            src: d.source,
            code: d.code,
            off,
            ssid: String::new(),
            mac: String::new(),
            reason: 0,
            raw: vec![],
        };
        if d.data.is_null() || size == 0 {
            // без данных
        } else if d.source == SRC_ONEX {
            item.raw = unsafe { std::slice::from_raw_parts(d.data as *const u8, size.min(4096)) }.to_vec();
        } else if d.source == SRC_ACM
            && matches!(off, ACM_ATTEMPT_FAIL | ACM_DISCONNECTED | ACM_CONNECTION_COMPLETE | 9)
            && size >= std::mem::size_of::<WlanConnectionNotificationData>()
        {
            let c = unsafe { &*(d.data as *const WlanConnectionNotificationData) };
            item.ssid = ssid_str(&c.ssid);
            item.reason = c.reason;
        } else if d.source == SRC_MSM && size >= std::mem::size_of::<WlanMsmNotificationData>() {
            let m = unsafe { &*(d.data as *const WlanMsmNotificationData) };
            item.ssid = ssid_str(&m.ssid);
            item.mac = mac(&m.mac);
            item.reason = m.reason;
        }
        let mut q = QUEUE.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() == 1000 {
            q.pop_front();
        }
        q.push_back(item);
    }));
}

// ---------------------------------------------------------------- монитор

struct Monitor {
    sink: Arc<dyn ConnSink>,
    interface_index: usize,
    interval: f64,
    ip_tick: u64,
}

fn query_u32(h: HANDLE, guid: &GUID, opcode: u32) -> Option<u32> {
    let (mut size, mut p, mut vt) = (0u32, std::ptr::null_mut::<c_void>(), 0u32);
    let rc = unsafe { WlanQueryInterface(h, guid, opcode, std::ptr::null_mut(), &mut size, &mut p, &mut vt) };
    if rc != 0 || p.is_null() {
        return None;
    }
    let v = unsafe { *(p as *const u32) };
    unsafe { WlanFreeMemory(p) };
    Some(v)
}

fn sample(h: HANDLE, guid: &GUID) -> ConnSample {
    let t = now_unix();
    let (mut size, mut p, mut vt) = (0u32, std::ptr::null_mut::<c_void>(), 0u32);
    let rc = unsafe {
        WlanQueryInterface(
            h,
            guid,
            OP_CURRENT_CONNECTION,
            std::ptr::null_mut(),
            &mut size,
            &mut p,
            &mut vt,
        )
    };
    if rc != 0 || p.is_null() {
        let st = query_u32(h, guid, OP_INTERFACE_STATE)
            .map(|v| if_state(v).unwrap_or("disconnected"))
            .unwrap_or("disconnected");
        return ConnSample::down(t, st);
    }
    let a = unsafe { &*(p as *const WlanConnectionAttributes) };
    let r1 = |v: u32| crate::ie::round1(v as f64 / 1000.0);
    let mut s = ConnSample {
        t,
        state: if_state(a.state).unwrap_or("unknown").into(),
        ssid: ssid_str(&a.assoc.ssid),
        bssid: mac(&a.assoc.bssid),
        quality: Some(a.assoc.signal_quality as i32),
        rx_mbps: Some(r1(a.assoc.rx_rate)),
        tx_mbps: Some(r1(a.assoc.tx_rate)),
        auth: auth_name(a.security.auth_algorithm),
        cipher: cipher_name(a.security.cipher_algorithm),
        onex: a.security.onex_enabled != 0,
        profile: u16_str(&a.profile),
        ..ConnSample::default()
    };
    unsafe { WlanFreeMemory(p) };
    if s.state == "connected" {
        s.rssi = query_u32(h, guid, OP_RSSI).map(|v| v as i32);
        s.channel = query_u32(h, guid, OP_CHANNEL_NUMBER).map(|v| v as i32);
    }
    s
}

fn opt_str<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "None".into())
}

fn onex(c: &mut ConnTracker, t: f64, code: u32, raw: &[u8]) {
    let name = if code == ONEX_RESULT_UPDATE && raw.len() >= 12 {
        let r = parse_result_update(raw);
        let reason = if r.reason != 0 {
            reason_text(r.reason)
        } else {
            String::new()
        };
        let err = if r.error != 0 {
            r.error
        } else {
            r.eap_win_error.unwrap_or(0)
        };
        c.sessions.onex(
            t,
            r.status.map_or(5, |s| s as i64),
            r.reason as i64,
            &reason,
            err as i64,
            &if err != 0 { win_error_text(err) } else { String::new() },
            r.eap_type.map(|e| e as i64),
            r.identity.map(|i| i as i64),
            false,
        );
        format!(
            "onex_result status={} reason=0x{:X} error=0x{:X} eap={} identity={}",
            opt_str(r.status),
            r.reason,
            err,
            opt_str(r.eap_type),
            opt_str(r.identity)
        )
    } else if code == ONEX_AUTH_RESTARTED {
        let (r, text) = parse_restart(raw);
        c.sessions.onex(t, 1, 0, &text, 0, "", None, None, true);
        format!("onex_restart reason={}", opt_str(r))
    } else {
        format!("onex_code{code}")
    };
    // сырые байты 802.1X сохраняем: разбор ещё не проверен на реальном адаптере
    let hex: String = raw.iter().take(96).map(|b| format!("{b:02x}")).collect();
    c.add_raw(t, SRC_ONEX, code, &format!("{name} hex={hex}"));
}

fn handle_item(c: &mut ConnTracker, it: &Item) {
    if it.src == SRC_ONEX {
        onex(c, it.t, it.off, &it.raw);
        return;
    }
    let (prefix, label, stage) = match it.src {
        SRC_ACM => ("acm_", acm_name(it.off), acm_stage(it.off)),
        SRC_MSM => ("msm_", msm_name(it.off), msm_stage(it.off)),
        _ => ("", None, None),
    };
    let name = if prefix.is_empty() {
        format!("src{}_code{}", it.src, it.off)
    } else {
        format!(
            "{prefix}{}",
            label.map(String::from).unwrap_or(format!("code{}", it.off))
        )
    };
    let text = if it.reason != 0 {
        reason_text(it.reason)
    } else {
        String::new()
    };
    let shown = if text.is_empty() {
        name
    } else {
        format!("{name} ({text})")
    };
    c.add_raw(it.t, it.src, it.code, &shown);
    if let Some(stage) = stage {
        let code = (it.reason != 0).then_some(it.reason as i64);
        c.sessions.stage(it.t, stage, &it.ssid, &it.mac, code, &text);
    }
    if it.src == SRC_ACM && it.off == ACM_DISCONNECTED && it.reason != 0 {
        c.add_reason(it.t, "disconnected", Some(it.reason as i64), &text, &it.ssid, "");
    } else if it.src == SRC_ACM && it.off == ACM_ATTEMPT_FAIL {
        let why = if text.is_empty() {
            tr("причина не указана")
        } else {
            text.clone()
        };
        c.add_reason(it.t, "attempt_fail", Some(it.reason as i64), &why, &it.ssid, "");
    }
}

impl Monitor {
    fn status(&self, text: String) {
        self.sink.with_conn(&mut |c| c.status = text.clone());
    }

    fn drain(&self) {
        let items: Vec<Item> = QUEUE.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
        for it in &items {
            self.sink.with_conn(&mut |c| handle_item(c, it));
        }
    }

    /// IPv4 и аренда DHCP: пока последняя сессия ждёт адрес; иначе раз в 10 секунд - «последний известный».
    fn poll_ip(&mut self, t: f64, gstr: &str) {
        let mut need = false;
        self.sink.with_conn(&mut |c| {
            need = c.sessions.last_connected(t, crate::session::IP_WAIT_S).is_some();
        });
        if !need {
            self.ip_tick += 1;
            need = self.ip_tick % 10 == 1;
        }
        if !need {
            return;
        }
        if let Some((ip, dhcp, server, lease)) = adapter_ip(gstr) {
            self.sink.with_conn(&mut |c| {
                c.sessions.ip_update(t, &ip, Some(dhcp), &server, lease);
            });
        }
    }

    fn run(mut self, stop: std::sync::mpsc::Receiver<()>) {
        let lang = self.sink.lang();
        let s = match Session::open() {
            Ok(s) => s,
            Err(_) => return self.status(with_lang(lang, || tr("ошибка: не удалось открыть WLAN API"))),
        };
        let ifaces = match s.interfaces() {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => return self.status(with_lang(lang, || tr("Wi-Fi адаптер не найден"))),
            Err(e) => return self.status(with_lang(lang, || trf("ошибка монитора: %s", &[Arg::S(e)]))),
        };
        let (desc, guid) = &ifaces[self.interface_index.min(ifaces.len() - 1)];
        let mut prev = 0u32;
        let (mut rc, mut mode) = (ERROR_ACCESS_DENIED, String::new());
        for (mask, label) in [
            (SRC_ACM | SRC_MSM | SRC_ONEX, "ACM, MSM и 802.1X"),
            (SRC_ACM | SRC_ONEX, "ACM и 802.1X (MSM запрещён системой)"),
            (SRC_ACM | SRC_MSM, "ACM и MSM (802.1X запрещён системой)"),
            (SRC_ACM, "только ACM"),
        ] {
            rc = unsafe {
                WlanRegisterNotification(
                    s.0,
                    mask,
                    1,
                    Some(on_notification),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut prev,
                )
            };
            mode = label.to_string();
            if rc != ERROR_ACCESS_DENIED {
                break;
            }
        }
        let registered = rc == 0;
        let lang = self.sink.lang();
        let status = with_lang(lang, || {
            let note = if registered {
                trf("уведомления: %s", &[Arg::S(tr(&mode))])
            } else {
                trf("уведомления недоступны (код %d), только опрос", &[Arg::I(rc as i64)])
            };
            trf(
                "опрос раз в %g с, %s, адаптер: %s",
                &[Arg::F(self.interval), Arg::S(note), Arg::S(desc.clone())],
            )
        });
        self.status(status);
        let gstr = guid_str(guid);
        loop {
            let smp = sample(s.0, guid);
            let t = smp.t;
            self.sink.with_conn(&mut |c| {
                c.add_sample(smp.clone());
            });
            self.drain();
            self.poll_ip(t, &gstr);
            match stop.recv_timeout(Duration::from_secs_f64(self.interval)) {
                Err(RecvTimeoutError::Timeout) => continue,
                _ => break,
            }
        }
        if registered {
            unsafe {
                WlanRegisterNotification(
                    s.0,
                    0,
                    1,
                    None,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
        }
    }
}

struct Handle(Mutex<Option<Sender<()>>>);

impl MonitorHandle for Handle {
    fn stop(&self) {
        if let Some(tx) = self.0.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(());
        }
    }
}

/// Запуск монитора в своём потоке.
pub fn start(sink: Arc<dyn ConnSink>, interface_index: usize) -> Result<Box<dyn MonitorHandle>, String> {
    let (tx, rx) = channel();
    let m = Monitor {
        sink,
        interface_index,
        interval: 1.0,
        ip_tick: 0,
    };
    std::thread::Builder::new()
        .name("conn-monitor".into())
        .spawn(move || {
            let sink = Arc::clone(&m.sink);
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| m.run(rx))).is_err() {
                let lang = sink.lang();
                let text = with_lang(lang, || trf("ошибка монитора: %s", &[Arg::S("panic".into())]));
                sink.with_conn(&mut |c| c.status = text.clone());
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(Box::new(Handle(Mutex::new(Some(tx)))))
}
