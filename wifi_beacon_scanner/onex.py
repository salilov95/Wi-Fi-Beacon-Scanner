"""Разбор уведомлений 802.1X (источник ONEX у WlanRegisterNotification).

Раскладка по onexstruct.h / dot1x.h (Windows SDK):

  ONEX_NOTIFICATION_TYPE: 1 = ResultUpdate (данные ONEX_RESULT_UPDATE_DATA), 2 = AuthRestarted (данные -
  причина ONEX_AUTH_RESTART_REASON, DWORD).

  ONEX_RESULT_UPDATE_DATA
     0  ONEX_STATUS { ONEX_AUTH_STATUS authStatus; DWORD dwReason; DWORD dwError; }
    12  ONEX_EAP_METHOD_BACKEND_SUPPORT BackendSupport
    16  BOOL fBackendEngaged
    20  DWORD fOneXAuthParams:1, fEapError:1
    24  ONEX_VARIABLE_BLOB authParams { DWORD dwSize; DWORD dwOffset; }
    32  ONEX_VARIABLE_BLOB eapError
  Смещение blob - от начала ONEX_RESULT_UPDATE_DATA.

  EAP_ERROR (в eapError): 0 dwWinError, 4 EAP_METHOD_TYPE { EAP_TYPE { BYTE type; DWORD vendorId;
  DWORD vendorType } eapType; DWORD dwAuthorId }, 20 dwReasonCode.
  ONEX_AUTH_PARAMS (в authParams): 0 fUpdatePending, 4 oneXConnProfile (blob), 12 authIdentity.

Разбор защищён проверками длины: если поле выходит за пределы данных, оно просто не заполняется.
На реальном адаптере ещё не проверено, поэтому сырые байты уведомления сохраняются для отладки.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, Optional

ONEX_RESULT_UPDATE = 1
ONEX_AUTH_RESTARTED = 2
# ONEX_AUTH_RESTART_REASON
RESTART_REASON_RU = {0: "инициировала сеть (аутентификатор)", 1: "по запросу Windows (MSM)",
                     2: "тайм-аут состояния held", 3: "тайм-аут аутентификации", 4: "изменились настройки 802.1X",
                     5: "сменился пользователь", 6: "изменилось состояние карантина",
                     7: "попытка с другими учётными данными"}


def _u32(b: bytes, off: int) -> Optional[int]:
    return struct.unpack_from("<I", b, off)[0] if len(b) >= off + 4 else None


def _blob(b: bytes, off: int) -> Optional[bytes]:
    size, offset = _u32(b, off), _u32(b, off + 4)
    if not size or offset is None or offset + size > len(b) or offset < 40:
        return None
    return b[offset:offset + size]


def parse_result_update(b: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": _u32(b, 0), "reason": _u32(b, 4) or 0, "error": _u32(b, 8) or 0,
                           "backend": _u32(b, 12), "eap_type": None, "identity": None, "eap_reason": None,
                           "eap_win_error": None}
    flags = _u32(b, 20) or 0
    if flags & 2:
        e = _blob(b, 32)
        if e is not None and len(e) >= 24:
            out["eap_win_error"] = _u32(e, 0)
            out["eap_type"] = e[4]
            out["eap_reason"] = _u32(e, 20)
    if flags & 1:
        a = _blob(b, 24)
        if a is not None and len(a) >= 16:
            ident = _u32(a, 12)
            if ident is not None and ident <= 5:
                out["identity"] = ident
    return out


def parse_restart(b: bytes) -> Dict[str, Any]:
    r = _u32(b, 0)
    return {"reason": r, "reason_ru": RESTART_REASON_RU.get(r, str(r)) if r is not None else ""}
