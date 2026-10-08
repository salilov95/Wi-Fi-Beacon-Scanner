"""Структуры Native Wifi API для журнала подключения.

Описаны по wlanapi.h / l2cmn.h (сверено с документацией Microsoft и заголовками mingw-w64).
WCHAR-массивы заданы как uint16, а не c_wchar: на Windows это одно и то же (2 байта), зато размеры
структур одинаковы на любой ОС и проверяются тестом без Windows.
"""
from __future__ import annotations

import ctypes
from ctypes import Structure, c_int32, c_ubyte, c_uint16, c_uint32, c_void_p

WLAN_MAX_NAME_LENGTH = 256


class GUID(Structure):
    _fields_ = [("Data1", c_uint32), ("Data2", c_uint16), ("Data3", c_uint16), ("Data4", c_ubyte * 8)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", c_uint32), ("ucSSID", c_ubyte * 32)]


class WLAN_ASSOCIATION_ATTRIBUTES(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", c_uint32),
        ("dot11Bssid", c_ubyte * 6),
        ("dot11PhyType", c_uint32),
        ("uDot11PhyIndex", c_uint32),
        ("wlanSignalQuality", c_uint32),   # 0..100
        ("ulRxRate", c_uint32),            # кбит/с
        ("ulTxRate", c_uint32),
    ]


class WLAN_SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ("bSecurityEnabled", c_int32),
        ("bOneXEnabled", c_int32),
        ("dot11AuthAlgorithm", c_uint32),
        ("dot11CipherAlgorithm", c_uint32),
    ]


class WLAN_CONNECTION_ATTRIBUTES(Structure):
    _fields_ = [
        ("isState", c_uint32),
        ("wlanConnectionMode", c_uint32),
        ("strProfileName", c_uint16 * WLAN_MAX_NAME_LENGTH),
        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
        ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES),
    ]


class WLAN_NOTIFICATION_DATA(Structure):          # = L2_NOTIFICATION_DATA
    _fields_ = [
        ("NotificationSource", c_uint32),
        ("NotificationCode", c_uint32),
        ("InterfaceGuid", GUID),
        ("dwDataSize", c_uint32),
        ("pData", c_void_p),
    ]


class WLAN_CONNECTION_NOTIFICATION_DATA(Structure):
    _fields_ = [                                   # за dwFlags идёт strProfileXml переменной длины - не читаем
        ("wlanConnectionMode", c_uint32),
        ("strProfileName", c_uint16 * WLAN_MAX_NAME_LENGTH),
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", c_uint32),
        ("bSecurityEnabled", c_int32),
        ("wlanReasonCode", c_uint32),
        ("dwFlags", c_uint32),
    ]


class WLAN_MSM_NOTIFICATION_DATA(Structure):
    _fields_ = [
        ("wlanConnectionMode", c_uint32),
        ("strProfileName", c_uint16 * WLAN_MAX_NAME_LENGTH),
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", c_uint32),
        ("dot11MacAddr", c_ubyte * 6),
        ("bSecurityEnabled", c_int32),
        ("bFirstPeer", c_int32),
        ("bLastPeer", c_int32),
        ("wlanReasonCode", c_uint32),
    ]


# Ожидаемые размеры для Windows x64 (на x86 у WLAN_NOTIFICATION_DATA указатель 4 байта -> 32).
EXPECTED_SIZES_X64 = {
    "WLAN_CONNECTION_ATTRIBUTES": 604,
    "WLAN_NOTIFICATION_DATA": 40,
    "WLAN_CONNECTION_NOTIFICATION_DATA": 568,
    "WLAN_MSM_NOTIFICATION_DATA": 580,
}

# opcode для WlanQueryInterface (wlan_intf_opcode_*)
OP_INTERFACE_STATE = 6
OP_CURRENT_CONNECTION = 7
OP_CHANNEL_NUMBER = 8
OP_RSSI = 0x10000102

# источники уведомлений (L2_NOTIFICATION_SOURCE_*)
SRC_ONEX = 0x04
SRC_ACM = 0x08
SRC_MSM = 0x10

# Коды уведомлений. По mingw-w64 нумерация начинается с L2_NOTIFICATION_CODE_PUBLIC_BEGIN (0),
# по странице Microsoft для ACM - с L2_NOTIFICATION_CODE_V2_BEGIN (0x1000). Смещение внутри
# группы одинаковое, поэтому сравниваем code & 0x0FFF: работает при любой базе.
ACM_NAMES = {
    7: "scan_complete", 8: "scan_fail", 9: "connection_start", 10: "connection_complete",
    11: "connection_attempt_fail", 18: "network_not_available", 19: "network_available",
    20: "disconnecting", 21: "disconnected",
}
ACM_CONNECTION_COMPLETE, ACM_ATTEMPT_FAIL, ACM_DISCONNECTED = 10, 11, 21
MSM_NAMES = {
    1: "associating", 2: "associated", 3: "authenticating", 4: "connected", 5: "roaming_start",
    6: "roaming_end", 7: "radio_state_change", 8: "signal_quality_change", 9: "disassociating",
    10: "disconnected", 15: "link_degraded", 16: "link_improved",
}

IF_STATE = {0: "not_ready", 1: "connected", 2: "ad_hoc", 3: "disconnecting", 4: "disconnected",
            5: "associating", 6: "discovering", 7: "authenticating"}

# DOT11_AUTH_ALGORITHM / DOT11_CIPHER_ALGORITHM: подписаны только значения, в которых уверен;
# остальные показываются числом, чтобы не выдавать догадку за факт.
AUTH_NAMES = {1: "Open", 2: "Shared key", 3: "WPA", 4: "WPA-PSK", 5: "WPA-None", 6: "WPA2 (RSNA)", 7: "WPA2-PSK"}
CIPHER_NAMES = {0: "нет", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 0x100: "use group", 0x101: "WEP"}


def norm_code(code: int) -> int:
    return code & 0x0FFF


def u16_str(arr) -> str:
    """WCHAR[] (как uint16) -> str до первого нуля."""
    chars = []
    for v in arr:
        if v == 0:
            break
        chars.append(v)
    return bytes(b for v in chars for b in (v & 0xFF, v >> 8)).decode("utf-16-le", "replace")


def ssid_str(s: DOT11_SSID) -> str:
    n = min(int(s.uSSIDLength), 32)
    return bytes(s.ucSSID[:n]).decode("utf-8", "replace")


def mac_str(m) -> str:
    return ":".join("%02x" % x for x in m)


def auth_name(v: int) -> str:
    return AUTH_NAMES.get(v, "auth %d" % v)


def cipher_name(v: int) -> str:
    return CIPHER_NAMES.get(v, "cipher %d" % v)


def sizes() -> dict:
    return {n: ctypes.sizeof(globals()[n]) for n in EXPECTED_SIZES_X64}
