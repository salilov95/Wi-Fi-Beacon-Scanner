"""Монитор подключения ноутбука на Windows.

Два источника:
  1. Опрос раз в секунду: WlanQueryInterface(current_connection) + rssi + channel_number.
     Это основной источник: из смены BSSID получаем роуминги, из смены состояния - обрывы.
  2. Уведомления WlanRegisterNotification: из них берутся коды причин обрывов и неудачных
     подключений. По документации MSM-уведомления требуют capability wiFiControl; если Windows
     отказывает (ERROR_ACCESS_DENIED), подписываемся только на ACM, а роуминг всё равно виден из опроса.

  3. Уведомления 802.1X (источник ONEX): результат EAP, причина отказа, тип EAP, чья учётка.
  4. Раз в секунду, пока подключение свежее, - IPv4 и аренда DHCP адаптера (GetAdaptersInfo).
Уведомления ACM/MSM/ONEX и IP складываются ещё и в машину состояний (session.py): стадии подключения
и роуминга с длительностями.

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

from . import ip_win
from . import onex as ox
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


_k32 = ctypes.windll.kernel32
FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS = 0x1000, 0x200

# ACM / MSM -> стадии машины состояний (session.py)
ACM_STAGE = {9: "start", 10: "complete", 11: "fail", 21: "disconnected"}
MSM_STAGE = {1: "associating", 2: "associated", 3: "authenticating", 4: "connected", 5: "roam_start",
             6: "roam_end", 9: "disassociating", 10: "disconnected"}


def win_error_text(code: int) -> str:
    """Текст системной ошибки (в том числе EAP HRESULT, если он есть в таблицах Windows)."""
    if not code:
        return ""
    buf = ctypes.create_unicode_buffer(512)
    n = _k32.FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, None, c_uint32(code), 0,
                            buf, 512, None)
    return buf.value.strip() if n else "ошибка 0x%08X" % code


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
            if src == ws.SRC_ONEX:
                raw = ctypes.string_at(d.pData, min(size, 4096)) if d.pData and size else b""
                item = (time.time(), src, code, off, "", "", 0, raw)
            elif src == ws.SRC_ACM and off in (ws.ACM_ATTEMPT_FAIL, ws.ACM_DISCONNECTED, ws.ACM_CONNECTION_COMPLETE, 9) \
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

    def _onex(self, t: float, code: int, raw: bytes) -> None:
        ses = self.tracker.sessions
        if code == ox.ONEX_RESULT_UPDATE and len(raw) >= 12:
            r = ox.parse_result_update(raw)
            reason = reason_text(r["reason"]) if r["reason"] else ""
            err = r["error"] or r["eap_win_error"] or 0
            ses.onex(t, r["status"] if r["status"] is not None else 5, r["reason"], reason, err,
                     win_error_text(err) if err else "", r["eap_type"], r["identity"])
            name = "onex_result status=%s reason=0x%X error=0x%X eap=%s identity=%s" % (
                r["status"], r["reason"], err, r["eap_type"], r["identity"])
        elif code == ox.ONEX_AUTH_RESTARTED:
            rr = ox.parse_restart(raw)
            ses.onex(t, 1, reason=rr["reason_ru"], restarted=True)
            name = "onex_restart reason=%s" % rr["reason"]
        else:
            name = "onex_code%d" % code
        # сырые байты 802.1X сохраняем: разбор ещё не проверен на реальном адаптере
        self.tracker.add_raw(t, ws.SRC_ONEX, code, name + " hex=" + raw[:96].hex())

    def _drain(self) -> None:
        while self._q:
            t, src, code, off, ssid, mac, reason, *rest = self._q.popleft()
            if src == ws.SRC_ONEX:
                with self.lock:
                    self._onex(t, off, rest[0] if rest else b"")
                continue
            names = ws.ACM_NAMES if src == ws.SRC_ACM else ws.MSM_NAMES if src == ws.SRC_MSM else {}
            name = ("acm_" if src == ws.SRC_ACM else "msm_" if src == ws.SRC_MSM else "src%d_" % src) + \
                names.get(off, "code%d" % off)
            text = reason_text(reason) if reason else ""
            stage = (ACM_STAGE if src == ws.SRC_ACM else MSM_STAGE if src == ws.SRC_MSM else {}).get(off)
            with self.lock:
                self.tracker.add_raw(t, src, code, name + (" (%s)" % text if text else ""))
                if stage:
                    self.tracker.sessions.stage(t, stage, ssid, mac, reason or None, text)
                if src == ws.SRC_ACM and off == ws.ACM_DISCONNECTED and reason:
                    self.tracker.add_reason(t, "disconnected", reason, text, ssid=ssid)
                elif src == ws.SRC_ACM and off == ws.ACM_ATTEMPT_FAIL:
                    self.tracker.add_reason(t, "attempt_fail", reason, text or "причина не указана", ssid=ssid)

    def _poll_ip(self, t: float, gstr: str) -> None:
        """IPv4 и аренда DHCP: только пока последняя сессия ждёт адрес (дёшево, но зачем зря)."""
        try:
            with self.lock:
                need = self.tracker.sessions.last_connected(t) is not None or self._ip_idle_tick()
            if not need:
                return
            info = ip_win.adapter_ip(gstr)
            if info is None:
                return
            with self.lock:
                self.tracker.sessions.ip_update(t, info["ip"], info["dhcp"], info["dhcp_server"], info["lease_obtained"])
        except Exception as e:  # noqa: BLE001 - IP-часть не должна ронять журнал
            self.tracker.add_raw(t, 0, 0, "ip_poll_error %s" % e)

    def _ip_idle_tick(self) -> bool:
        """Раз в 10 секунд обновляем «последний известный» адрес и аренду, чтобы было с чем сравнивать."""
        self._ip_tick = getattr(self, "_ip_tick", 0) + 1
        return self._ip_tick % 10 == 1

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
            rc, mode = ERROR_ACCESS_DENIED, ""
            for mask, label in ((ws.SRC_ACM | ws.SRC_MSM | ws.SRC_ONEX, "ACM, MSM и 802.1X"),
                                (ws.SRC_ACM | ws.SRC_ONEX, "ACM и 802.1X (MSM запрещён системой)"),
                                (ws.SRC_ACM | ws.SRC_MSM, "ACM и MSM (802.1X запрещён системой)"),
                                (ws.SRC_ACM, "только ACM")):
                rc = _w.WlanRegisterNotification(h, mask, 1, cb, None, None, byref(prev))
                mode = label
                if rc != ERROR_ACCESS_DENIED:
                    break
            registered = rc == 0
            note = "уведомления: %s" % mode if registered else "уведомления недоступны (код %d), только опрос" % rc
            self._set_status("опрос раз в %g с, %s, адаптер: %s" % (self.interval, note, desc))
            gstr = ip_win.guid_str(guid)
            while not self._halt.is_set():
                s = self._sample(h, guid)
                with self.lock:
                    self.tracker.add_sample(s)
                self._drain()
                self._poll_ip(s.t, gstr)
                self._halt.wait(self.interval)
        except Exception as e:  # noqa: BLE001
            self._set_status("ошибка монитора: %s" % e)
        finally:
            if registered:
                _w.WlanRegisterNotification(h, 0, 1, None, None, None, None)
            _w.WlanCloseHandle(h, None)
