//! Разбор уведомлений 802.1X (источник ONEX у WlanRegisterNotification). Перенос `wifi_beacon_scanner/onex.py`.
//!
//! Раскладка по onexstruct.h / dot1x.h (Windows SDK):
//! `ONEX_RESULT_UPDATE_DATA`: 0 authStatus, 4 dwReason, 8 dwError, 12 BackendSupport, 16 fBackendEngaged,
//! 20 флаги (бит 0 - есть authParams, бит 1 - есть eapError), 24 authParams {size, offset}, 32 eapError {size, offset};
//! смещение blob - от начала структуры. `EAP_ERROR`: 0 dwWinError, 4 тип EAP (байт), 20 dwReasonCode.
//! `ONEX_AUTH_PARAMS`: 12 authIdentity. Поле за пределами данных просто не заполняется.

use crate::i18n::tr;
use crate::json::Value;

pub const ONEX_RESULT_UPDATE: u32 = 1;
pub const ONEX_AUTH_RESTARTED: u32 = 2;

pub fn restart_reason_ru(r: u32) -> Option<&'static str> {
    Some(match r {
        0 => "инициировала сеть (аутентификатор)",
        1 => "по запросу Windows (MSM)",
        2 => "тайм-аут состояния held",
        3 => "тайм-аут аутентификации",
        4 => "изменились настройки 802.1X",
        5 => "сменился пользователь",
        6 => "изменилось состояние карантина",
        7 => "попытка с другими учётными данными",
        _ => return None,
    })
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

fn blob(b: &[u8], off: usize) -> Option<&[u8]> {
    let size = u32_at(b, off)? as usize;
    let offset = u32_at(b, off + 4)? as usize;
    if size == 0 || offset + size > b.len() || offset < 40 {
        return None;
    }
    Some(&b[offset..offset + size])
}

/// Итог 802.1X из `ONEX_RESULT_UPDATE_DATA`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResultUpdate {
    pub status: Option<u32>,
    pub reason: u32,
    pub error: u32,
    pub backend: Option<u32>,
    pub eap_type: Option<u8>,
    pub identity: Option<u32>,
    pub eap_reason: Option<u32>,
    pub eap_win_error: Option<u32>,
}

impl ResultUpdate {
    pub fn to_value(&self) -> Value {
        Value::Obj(vec![
            ("status".into(), self.status.into()),
            ("reason".into(), self.reason.into()),
            ("error".into(), self.error.into()),
            ("backend".into(), self.backend.into()),
            ("eap_type".into(), self.eap_type.into()),
            ("identity".into(), self.identity.into()),
            ("eap_reason".into(), self.eap_reason.into()),
            ("eap_win_error".into(), self.eap_win_error.into()),
        ])
    }
}

pub fn parse_result_update(b: &[u8]) -> ResultUpdate {
    let mut out = ResultUpdate {
        status: u32_at(b, 0),
        reason: u32_at(b, 4).unwrap_or(0),
        error: u32_at(b, 8).unwrap_or(0),
        backend: u32_at(b, 12),
        ..ResultUpdate::default()
    };
    let flags = u32_at(b, 20).unwrap_or(0);
    if flags & 2 != 0 {
        if let Some(e) = blob(b, 32).filter(|e| e.len() >= 24) {
            out.eap_win_error = u32_at(e, 0);
            out.eap_type = Some(e[4]);
            out.eap_reason = u32_at(e, 20);
        }
    }
    if flags & 1 != 0 {
        if let Some(a) = blob(b, 24).filter(|a| a.len() >= 16) {
            out.identity = u32_at(a, 12).filter(|&i| i <= 5);
        }
    }
    out
}

/// Причина перезапуска 802.1X: `(код, текст)`.
pub fn parse_restart(b: &[u8]) -> (Option<u32>, String) {
    let r = u32_at(b, 0);
    let text = match r {
        None => String::new(),
        Some(r) => restart_reason_ru(r).map(tr).unwrap_or_else(|| r.to_string()),
    };
    (r, text)
}
