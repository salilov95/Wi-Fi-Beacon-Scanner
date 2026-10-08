"""Сканер на Windows через wlanapi.dll (Native Wifi API), только stdlib (ctypes).

Как это работает:
  1. WlanOpenHandle - открыть сессию с WLAN-службой.
  2. WlanEnumInterfaces - получить список Wi-Fi адаптеров (у каждого свой GUID).
  3. WlanScan - попросить драйвер просканировать эфир. Вызов асинхронный: он возвращается
     сразу, результаты появятся через несколько секунд.
  4. WlanGetNetworkBssList - забрать список BSS. На каждый BSS приходит структура
     WLAN_BSS_ENTRY, а за ней - сырые байты IE (их разбирает ie.py).
  5. WlanFreeMemory / WlanCloseHandle - освободить память и закрыть сессию.

Это НЕ monitor mode: мы видим то, что кэширует драйвер/служба. Ретрансмиты, EAPOL
и roaming-кадры так не увидеть.
"""
from __future__ import annotations

import ctypes
import sys
import time
from ctypes import POINTER, Structure, byref, c_int32, c_ubyte, c_uint, c_uint16, c_uint32, c_uint64, c_void_p
from typing import List, Optional, Tuple

from .model import Bss, Snapshot, now_iso

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("scanner_win работает только на Windows")

ERROR_SUCCESS = 0
DOT11_BSS_TYPE_ANY = 3


class GUID(Structure):
    _fields_ = [("Data1", c_uint32), ("Data2", c_uint16), ("Data3", c_uint16), ("Data4", c_ubyte * 8)]


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256), ("isState", c_uint)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", c_uint32), ("ucSSID", c_ubyte * 32)]


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", c_uint32), ("usRateSet", c_uint16 * 126)]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", c_uint32),
        ("dot11Bssid", c_ubyte * 6),
        ("dot11BssType", c_uint),
        ("dot11BssPhyType", c_uint),
        ("lRssi", c_int32),
        ("uLinkQuality", c_uint32),
        ("bInRegDomain", c_ubyte),
        ("usBeaconPeriod", c_uint16),
        ("ullTimestamp", c_uint64),
        ("ullHostTimestamp", c_uint64),
        ("usCapabilityInformation", c_uint16),
        ("ulChCenterFrequency", c_uint32),   # в кГц
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", c_uint32),            # смещение IE от НАЧАЛА этой структуры
        ("ulIeSize", c_uint32),
    ]


# Размер из заголовка wlanapi.h должен быть 360 байт. Если нет - раскладка структуры
# в ctypes не совпала с Windows и результаты будут мусором.
EXPECTED_BSS_ENTRY_SIZE = 360

_wlan = ctypes.WinDLL("wlanapi")
_wlan.WlanOpenHandle.argtypes = [c_uint32, c_void_p, POINTER(c_uint32), POINTER(c_void_p)]
_wlan.WlanOpenHandle.restype = c_uint32
_wlan.WlanCloseHandle.argtypes = [c_void_p, c_void_p]
_wlan.WlanCloseHandle.restype = c_uint32
_wlan.WlanEnumInterfaces.argtypes = [c_void_p, c_void_p, POINTER(c_void_p)]
_wlan.WlanEnumInterfaces.restype = c_uint32
_wlan.WlanScan.argtypes = [c_void_p, POINTER(GUID), c_void_p, c_void_p, c_void_p]
_wlan.WlanScan.restype = c_uint32
_wlan.WlanGetNetworkBssList.argtypes = [c_void_p, POINTER(GUID), c_void_p, c_uint, ctypes.c_int, c_void_p, POINTER(c_void_p)]
_wlan.WlanGetNetworkBssList.restype = c_uint32
_wlan.WlanFreeMemory.argtypes = [c_void_p]
_wlan.WlanFreeMemory.restype = None


def _check(code: int, what: str) -> None:
    if code != ERROR_SUCCESS:
        raise OSError("%s: код ошибки %d (%s)" % (what, code, ctypes.FormatError(code).strip()))


def list_interfaces() -> List[Tuple[str, GUID]]:
    handle = c_void_p()
    ver = c_uint32()
    _check(_wlan.WlanOpenHandle(2, None, byref(ver), byref(handle)), "WlanOpenHandle")
    try:
        return _enum(handle)
    finally:
        _wlan.WlanCloseHandle(handle, None)


def _enum(handle) -> List[Tuple[str, GUID]]:
    p = c_void_p()
    _check(_wlan.WlanEnumInterfaces(handle, None, byref(p)), "WlanEnumInterfaces")
    try:
        count = c_uint32.from_address(p.value).value            # dwNumberOfItems
        base = p.value + 8                                      # пропускаем dwNumberOfItems + dwIndex
        res = []
        for i in range(count):
            info = WLAN_INTERFACE_INFO.from_address(base + i * ctypes.sizeof(WLAN_INTERFACE_INFO))
            guid = GUID()
            ctypes.memmove(byref(guid), byref(info.InterfaceGuid), ctypes.sizeof(GUID))
            res.append((info.strInterfaceDescription, guid))
        return res
    finally:
        _wlan.WlanFreeMemory(p)


def scan(interface_index: int = 0, wait_s: float = 5.0) -> Snapshot:
    if ctypes.sizeof(WLAN_BSS_ENTRY) != EXPECTED_BSS_ENTRY_SIZE:
        raise RuntimeError("sizeof(WLAN_BSS_ENTRY)=%d, ожидалось %d: раскладка структуры неверна"
                           % (ctypes.sizeof(WLAN_BSS_ENTRY), EXPECTED_BSS_ENTRY_SIZE))
    handle = c_void_p()
    ver = c_uint32()
    _check(_wlan.WlanOpenHandle(2, None, byref(ver), byref(handle)), "WlanOpenHandle")
    try:
        ifaces = _enum(handle)
        if not ifaces:
            raise OSError("Wi-Fi адаптеры не найдены")
        if interface_index >= len(ifaces):
            raise OSError("Нет адаптера с индексом %d (всего %d)" % (interface_index, len(ifaces)))
        desc, guid = ifaces[interface_index]
        # Запуск скана: код != 0 не фатален (служба может отклонить слишком частый запрос,
        # тогда просто читаем то, что уже в кэше).
        rc = _wlan.WlanScan(handle, byref(guid), None, None, None)
        if rc != ERROR_SUCCESS:
            print("предупреждение: WlanScan вернул %d (%s), читаю кэш" % (rc, ctypes.FormatError(rc).strip()),
                  file=sys.stderr)
        time.sleep(wait_s)
        p = c_void_p()
        _check(_wlan.WlanGetNetworkBssList(handle, byref(guid), None, DOT11_BSS_TYPE_ANY, 0, None, byref(p)),
               "WlanGetNetworkBssList")
        try:
            n = c_uint32.from_address(p.value + 4).value        # dwNumberOfItems (после dwTotalSize)
            first = p.value + 8
            esz = ctypes.sizeof(WLAN_BSS_ENTRY)
            result: List[Bss] = []
            for i in range(n):
                addr = first + i * esz
                e = WLAN_BSS_ENTRY.from_address(addr)
                ie = ctypes.string_at(addr + e.ulIeOffset, e.ulIeSize) if e.ulIeSize else b""
                ssid = bytes(e.dot11Ssid.ucSSID[: e.dot11Ssid.uSSIDLength])
                result.append(Bss(
                    bssid=":".join("%02x" % x for x in e.dot11Bssid),
                    ssid_bytes=ssid,
                    rssi=e.lRssi,
                    link_quality=e.uLinkQuality,
                    freq_khz=e.ulChCenterFrequency,
                    beacon_interval=e.usBeaconPeriod,
                    capability=e.usCapabilityInformation,
                    phy_type=e.dot11BssPhyType,
                    ie_raw=ie,
                ))
        finally:
            _wlan.WlanFreeMemory(p)
        return Snapshot(taken_at=now_iso(), interface=desc, bss=result)
    finally:
        _wlan.WlanCloseHandle(handle, None)
