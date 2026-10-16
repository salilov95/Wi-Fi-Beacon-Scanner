//! Чтение журнала WLAN-AutoConfig/Operational через wevtapi. Перенос `winlog_win.py`.
//!
//! `EvtQuery` за последние N часов (новые первыми) → `EvtNext` пачками по 64 → `EvtRender` (XML) +
//! `EvtFormatMessage` (текст события на языке Windows). Если журнал недоступен - понятная ошибка.

use std::ffi::c_void;

use crate::i18n::{trf, Arg};
use crate::json::Value;
use crate::winlog::{parse_event_xml, CHANNEL, PUBLISHER};

type Evt = *mut c_void;

const EVT_QUERY_CHANNEL_PATH: u32 = 0x1;
const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x200;
const EVT_RENDER_EVENT_XML: u32 = 1;
const EVT_FORMAT_MESSAGE_EVENT: u32 = 1;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

#[cfg_attr(windows, link(name = "wevtapi", kind = "raw-dylib"))]
extern "system" {
    fn EvtQuery(session: Evt, path: *const u16, query: *const u16, flags: u32) -> Evt;
    fn EvtNext(result_set: Evt, count: u32, events: *mut Evt, timeout: u32, flags: u32, returned: *mut u32) -> i32;
    fn EvtRender(
        context: Evt,
        fragment: Evt,
        flags: u32,
        buffer_size: u32,
        buffer: *mut c_void,
        used: *mut u32,
        property_count: *mut u32,
    ) -> i32;
    fn EvtOpenPublisherMetadata(
        session: Evt,
        publisher: *const u16,
        log_file: *const u16,
        locale: u32,
        flags: u32,
    ) -> Evt;
    #[allow(clippy::too_many_arguments)]
    fn EvtFormatMessage(
        metadata: Evt,
        event: Evt,
        message_id: u32,
        value_count: u32,
        values: *mut c_void,
        flags: u32,
        buffer_size: u32,
        buffer: *mut u16,
        used: *mut u32,
    ) -> i32;
    fn EvtClose(h: Evt) -> i32;
}

#[cfg_attr(windows, link(name = "kernel32", kind = "raw-dylib"))]
extern "system" {
    fn GetLastError() -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

fn render(ev: Evt) -> String {
    let (mut used, mut props) = (0u32, 0u32);
    unsafe {
        EvtRender(
            std::ptr::null_mut(),
            ev,
            EVT_RENDER_EVENT_XML,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut props,
        )
    };
    if used == 0 {
        return String::new();
    }
    // размер - в байтах, текст UTF-16
    let mut buf = vec![0u16; (used as usize).div_ceil(2)];
    let ok = unsafe {
        EvtRender(
            std::ptr::null_mut(),
            ev,
            EVT_RENDER_EVENT_XML,
            used,
            buf.as_mut_ptr() as *mut c_void,
            &mut used,
            &mut props,
        )
    };
    if ok == 0 {
        return String::new();
    }
    from_wide(&buf)
}

fn message(meta: Evt, ev: Evt) -> String {
    if meta.is_null() {
        return String::new();
    }
    let mut used = 0u32;
    unsafe {
        EvtFormatMessage(
            meta,
            ev,
            0,
            0,
            std::ptr::null_mut(),
            EVT_FORMAT_MESSAGE_EVENT,
            0,
            std::ptr::null_mut(),
            &mut used,
        )
    };
    if used == 0 {
        return String::new();
    }
    // размер - в символах
    let mut buf = vec![0u16; used as usize];
    let ok = unsafe {
        EvtFormatMessage(
            meta,
            ev,
            0,
            0,
            std::ptr::null_mut(),
            EVT_FORMAT_MESSAGE_EVENT,
            used,
            buf.as_mut_ptr(),
            &mut used,
        )
    };
    if ok == 0 {
        return String::new();
    }
    from_wide(&buf)
}

/// События за последние `hours` часов, новые первыми, не больше `limit`.
pub fn read_events(hours: f64, limit: usize) -> Result<Vec<Value>, String> {
    let ms = (hours * 3600.0 * 1000.0) as i64;
    let query = wide(&format!("*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"));
    let path = wide(CHANNEL);
    let q = unsafe {
        EvtQuery(
            std::ptr::null_mut(),
            path.as_ptr(),
            query.as_ptr(),
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION,
        )
    };
    if q.is_null() {
        let err = unsafe { GetLastError() };
        let ch = Arg::S(CHANNEL.into());
        return Err(match err {
            ERROR_ACCESS_DENIED => trf("нет прав на чтение журнала %s", &[ch]),
            ERROR_EVT_CHANNEL_NOT_FOUND => trf("журнал %s не найден (нет службы WLAN?)", &[ch]),
            _ => trf("не удалось открыть журнал %s (код %d)", &[ch, Arg::I(err as i64)]),
        });
    }
    let publisher = wide(PUBLISHER);
    let meta = unsafe { EvtOpenPublisherMetadata(std::ptr::null_mut(), publisher.as_ptr(), std::ptr::null(), 0, 0) };
    let mut out = vec![];
    let mut arr: [Evt; 64] = [std::ptr::null_mut(); 64];
    while out.len() < limit {
        let mut n = 0u32;
        if unsafe { EvtNext(q, 64, arr.as_mut_ptr(), 2000, 0, &mut n) } == 0 {
            break;
        }
        for ev in arr.iter().take(n as usize) {
            let xml = render(*ev);
            if !xml.is_empty() {
                // одно битое событие не должно ронять чтение
                if let Ok(v) = parse_event_xml(&xml, &message(meta, *ev)) {
                    out.push(v);
                }
            }
            unsafe { EvtClose(*ev) };
        }
    }
    unsafe {
        if !meta.is_null() {
            EvtClose(meta);
        }
        EvtClose(q);
    }
    Ok(out)
}
