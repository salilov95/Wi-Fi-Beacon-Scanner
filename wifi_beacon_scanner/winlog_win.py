"""Чтение журнала WLAN-AutoConfig/Operational через wevtapi (Windows Vista+), без внешних модулей.

Текст события - из самой Windows (EvtFormatMessage, на языке системы). Если журнал недоступен
(нет прав, служба не установлена), поднимается OSError с понятным текстом.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import POINTER, byref, c_uint32, c_void_p, c_wchar_p
from typing import Any, Dict, List

from .i18n import tr
from .winlog import CHANNEL, PUBLISHER, parse_event_xml

EvtQueryChannelPath = 0x1
EvtQueryReverseDirection = 0x200
EvtRenderEventXml = 1
EvtFormatMessageEvent = 1
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259
ERROR_EVT_CHANNEL_NOT_FOUND = 15007
ERROR_ACCESS_DENIED = 5

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("winlog_win работает только на Windows")

_e = ctypes.WinDLL("wevtapi", use_last_error=True)
_e.EvtQuery.argtypes = [c_void_p, c_wchar_p, c_wchar_p, c_uint32]
_e.EvtQuery.restype = c_void_p
_e.EvtNext.argtypes = [c_void_p, c_uint32, POINTER(c_void_p), c_uint32, c_uint32, POINTER(c_uint32)]
_e.EvtNext.restype = ctypes.c_int
_e.EvtRender.argtypes = [c_void_p, c_void_p, c_uint32, c_uint32, c_void_p, POINTER(c_uint32), POINTER(c_uint32)]
_e.EvtRender.restype = ctypes.c_int
_e.EvtOpenPublisherMetadata.argtypes = [c_void_p, c_wchar_p, c_wchar_p, c_uint32, c_uint32]
_e.EvtOpenPublisherMetadata.restype = c_void_p
_e.EvtFormatMessage.argtypes = [c_void_p, c_void_p, c_uint32, c_uint32, c_void_p, c_uint32, c_uint32,
                                c_void_p, POINTER(c_uint32)]
_e.EvtFormatMessage.restype = ctypes.c_int
_e.EvtClose.argtypes = [c_void_p]
_e.EvtClose.restype = ctypes.c_int


def _render(ev) -> str:
    used, props = c_uint32(), c_uint32()
    _e.EvtRender(None, ev, EvtRenderEventXml, 0, None, byref(used), byref(props))
    if not used.value:
        return ""
    buf = ctypes.create_string_buffer(used.value)
    if not _e.EvtRender(None, ev, EvtRenderEventXml, used.value, buf, byref(used), byref(props)):
        return ""
    return buf.raw[:used.value].decode("utf-16-le", "replace").rstrip("\x00")


def _message(meta, ev) -> str:
    if not meta:
        return ""
    used = c_uint32()
    _e.EvtFormatMessage(meta, ev, 0, 0, None, EvtFormatMessageEvent, 0, None, byref(used))
    if not used.value:
        return ""
    buf = ctypes.create_unicode_buffer(used.value)
    if not _e.EvtFormatMessage(meta, ev, 0, 0, None, EvtFormatMessageEvent, used.value, buf, byref(used)):
        return ""
    return buf.value


def read_events(hours: float = 24, limit: int = 2000) -> List[Dict[str, Any]]:
    ms = int(hours * 3600 * 1000)
    q = _e.EvtQuery(None, CHANNEL, "*[System[TimeCreated[timediff(@SystemTime) <= %d]]]" % ms,
                    EvtQueryChannelPath | EvtQueryReverseDirection)
    if not q:
        err = ctypes.get_last_error()
        if err == ERROR_ACCESS_DENIED:
            raise OSError(tr("нет прав на чтение журнала %s") % CHANNEL)
        if err == ERROR_EVT_CHANNEL_NOT_FOUND:
            raise OSError(tr("журнал %s не найден (нет службы WLAN?)") % CHANNEL)
        raise OSError(tr("не удалось открыть журнал %s (код %d)") % (CHANNEL, err))
    meta = _e.EvtOpenPublisherMetadata(None, PUBLISHER, None, 0, 0)
    out: List[Dict[str, Any]] = []
    arr = (c_void_p * 64)()
    try:
        while len(out) < limit:
            n = c_uint32()
            if not _e.EvtNext(q, 64, arr, 2000, 0, byref(n)):
                break
            for i in range(n.value):
                ev = arr[i]
                try:
                    xml = _render(ev)
                    if xml:
                        out.append(parse_event_xml(xml, _message(meta, ev)))
                except Exception:  # noqa: BLE001 - одно битое событие не должно ронять чтение
                    pass
                finally:
                    _e.EvtClose(ev)
    finally:
        if meta:
            _e.EvtClose(meta)
        _e.EvtClose(q)
    return out
