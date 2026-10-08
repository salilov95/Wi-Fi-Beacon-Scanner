"""Монитор подключения ноутбука на Windows.

Два источника:
  1. Опрос раз в секунду: WlanQueryInterface(current_connection) + rssi + channel_number.
     Это основной источник: из смены BSSID получаем роуминги, из смены состояния - обрывы.
  2. Уведомления WlanRegisterNotification: из них берутся коды причин обрывов и неудачных
     подключений. По документации MSM-уведомления требуют capability wiFiControl; если Windows
     отказывает (ERROR_ACCESS_DENIED), подписываемся только на ACM, а роуминг всё равно виден из опроса.

Callback уведомлений вызывает служба WLAN в своём потоке: в нём только копируем данные в очередь,
вся обработка - в потоке монитора.
"""
from __future__ import annotations

import ctypes
import sys
import threading
import time
from collections import deque
from ctypes import POINTER, byref, c_int32, c_uint32, c_void_p
from typing import Any, Deque, Optional, Tuple

from . import scanner_win as sw
from . import winstructs as ws
from .conn import ConnSample, ConnTracker

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("conn_win работает только на Windows")

ERROR_ACCESS_DENIED = 5

NOTIF_CB = ctypes.WINFUNCTYPE(None, POINTER(ws.WLAN_NOTIFICATION_DATA), c_void_p)

_w = sw._wlan
_w.WlanQueryInterface.argtypes = [c_void_p, POINTER(sw.GUID), c_uint32, c_void_p, POINTER(c_uint32),
                                  POINTER(c_void_p), POINTER(c_uint32)]
_w.WlanQueryInterface.restype = c_uint32
_w.WlanRegisterNotification.argtypes = [c_void_p, c_uint32, c_int32, c_void_p, c_void_p, c_void_p, POINTER(c_uint32)]
_w.WlanRegisterNotification.restype = c_uint32
_w.WlanReasonCodeToString.argtypes = [c_uint32, c_uint32, ctypes.c_wchar_p, c_void_p]
_w.WlanReasonCodeToString.restype = c_uint32


def reason_text(code: int) -> str:
    if not code:
        return ""
    buf = ctypes.create_unicode_buffer(512)
    if _w.WlanReasonCodeToString(code, 512, buf, None) == 0 and buf.value:
        return buf.value
    return "код причины 0x%X" % code


class WinConnMonitor(threading.Thread):
    daemon = True

    def __init__(self, tracker: ConnTracker, lock: threading.Lock, interface_index: int = 0,
                 interval: float = 1.0) -> None:
        super().__init__(name="conn-monitor")
        self.tracker, self.lock = tracker, lock
        self.interface_index, self.interval = interface_index, interval
        self._halt = threading.Event()
        self._q: Deque[Tuple[Any, ...]] = deque(maxlen=1000)
        self._cb = NOTIF_CB(self._on_notification)     # держим ссылку, иначе callback соберёт GC

    def stop(self) -> None:
        self._halt.set()

    def _set_status(self, text: str) -> None:
        with self.lock:
            self.tracker.status = text

    # ---- callback из потока службы WLAN: только копирование ----
    def _on_notification(self, pdata, _ctx) -> None:
        try:
            d = pdata.contents
            src, code, size = int(d.NotificationSource), int(d.NotificationCode), int(d.dwDataSize)
            off = ws.norm_code(code)
            item: Tuple[Any, ...] = (time.time(), src, code, off, "", "", 0)
            if src == ws.SRC_ACM and off in (ws.ACM_ATTEMPT_FAIL, ws.ACM_DISCONNECTED, ws.ACM_CONNECTION_COMPLETE) \
                    and d.pData and size >= ctypes.sizeof(ws.WLAN_CONNECTION_NOTIFICATION_DATA):
                c = ws.WLAN_CONNECTION_NOTIFICATION_DATA.from_address(d.pData)
                item = (time.time(), src, code, off, ws.ssid_str(c.dot11Ssid), "", int(c.wlanReasonCode))
            elif src == ws.SRC_MSM and d.pData and size >= ctypes.sizeof(ws.WLAN_MSM_NOTIFICATION_DATA):
                m = ws.WLAN_MSM_NOTIFICATION_DATA.from_address(d.pData)
                item = (time.time(), src, code, off, ws.ssid_str(m.dot11Ssid), ws.mac_str(m.dot11MacAddr),
                        int(m.wlanReasonCode))
            self._q.append(item)
        except Exception:  # noqa: BLE001 - исключение в callback службы ничего хорошего не даст
            pass

    # ---- опрос ----
    def _query(self, h, guid, opcode) -> Optional[int]:
        p, size, vt = c_void_p(), c_uint32(), c_uint32()
        if _w.WlanQueryInterface(h, byref(guid), opcode, None, byref(size), byref(p), byref(vt)) != 0 or not p.value:
            return None
        try:
            return ctypes.c_int32.from_address(p.value).value if opcode == ws.OP_RSSI else \
                c_uint32.from_address(p.value).value
        finally:
            _w.WlanFreeMemory(p)

    def _sample(self, h, guid) -> ConnSample:
        t = time.time()
        p, size, vt = c_void_p(), c_uint32(), c_uint32()
        rc = _w.WlanQueryInterface(h, byref(guid), ws.OP_CURRENT_CONNECTION, None, byref(size), byref(p), byref(vt))
        if rc != 0 or not p.value:
            st = self._query(h, guid, ws.OP_INTERFACE_STATE)
            return ConnSample(t=t, state=ws.IF_STATE.get(st, "disconnected") if st is not None else "disconnected")
        try:
            a = ws.WLAN_CONNECTION_ATTRIBUTES.from_address(p.value)
            aa, sa = a.wlanAssociationAttributes, a.wlanSecurityAttributes
            s = ConnSample(
                t=t, state=ws.IF_STATE.get(int(a.isState), "unknown"),
                ssid=ws.ssid_str(aa.dot11Ssid), bssid=ws.mac_str(aa.dot11Bssid),
                quality=int(aa.wlanSignalQuality),
                rx_mbps=round(aa.ulRxRate / 1000.0, 1), tx_mbps=round(aa.ulTxRate / 1000.0, 1),
                auth=ws.auth_name(int(sa.dot11AuthAlgorithm)), cipher=ws.cipher_name(int(sa.dot11CipherAlgorithm)),
                onex=bool(sa.bOneXEnabled), profile=ws.u16_str(a.strProfileName),
            )
        finally:
            _w.WlanFreeMemory(p)
        if s.state == "connected":
            s.rssi = self._query(h, guid, ws.OP_RSSI)
            s.channel = self._query(h, guid, ws.OP_CHANNEL_NUMBER)
        return s

    def _drain(self) -> None:
        while self._q:
            t, src, code, off, ssid, mac, reason = self._q.popleft()
            names = ws.ACM_NAMES if src == ws.SRC_ACM else ws.MSM_NAMES if src == ws.SRC_MSM else {}
            name = ("acm_" if src == ws.SRC_ACM else "msm_" if src == ws.SRC_MSM else "src%d_" % src) + \
                names.get(off, "code%d" % off)
            text = reason_text(reason) if reason else ""
            with self.lock:
                self.tracker.add_raw(t, src, code, name + (" (%s)" % text if text else ""))
                if src == ws.SRC_ACM and off == ws.ACM_DISCONNECTED and reason:
                    self.tracker.add_reason(t, "disconnected", reason, text, ssid=ssid)
                elif src == ws.SRC_ACM and off == ws.ACM_ATTEMPT_FAIL:
                    self.tracker.add_reason(t, "attempt_fail", reason, text or "причина не указана", ssid=ssid)

    def run(self) -> None:
        bad = {k: v for k, v in ws.sizes().items()
               if ctypes.sizeof(c_void_p) == 8 and v != ws.EXPECTED_SIZES_X64[k]}
        if bad:
            self._set_status("ошибка: раскладка структур не совпала с Windows %s" % bad)
            return
        h, ver = c_void_p(), c_uint32()
        if _w.WlanOpenHandle(2, None, byref(ver), byref(h)) != 0:
            self._set_status("ошибка: не удалось открыть WLAN API")
            return
        registered = False
        try:
            ifaces = sw._enum(h)
            if not ifaces:
                self._set_status("Wi-Fi адаптер не найден")
                return
            desc, guid = ifaces[min(self.interface_index, len(ifaces) - 1)]
            prev = c_uint32()
            cb = ctypes.cast(self._cb, c_void_p)
            rc = _w.WlanRegisterNotification(h, ws.SRC_ACM | ws.SRC_MSM, 1, cb, None, None, byref(prev))
            mode = "ACM и MSM"
            if rc == ERROR_ACCESS_DENIED:
                rc = _w.WlanRegisterNotification(h, ws.SRC_ACM, 1, cb, None, None, byref(prev))
                mode = "только ACM (MSM запрещён системой)"
            registered = rc == 0
            note = "уведомления: %s" % mode if registered else "уведомления недоступны (код %d), только опрос" % rc
            self._set_status("опрос раз в %g с, %s, адаптер: %s" % (self.interval, note, desc))
            while not self._halt.is_set():
                s = self._sample(h, guid)
                with self.lock:
                    self.tracker.add_sample(s)
                self._drain()
                self._halt.wait(self.interval)
        except Exception as e:  # noqa: BLE001
            self._set_status("ошибка монитора: %s" % e)
        finally:
            if registered:
                _w.WlanRegisterNotification(h, 0, 1, None, None, None, None)
            _w.WlanCloseHandle(h, None)
