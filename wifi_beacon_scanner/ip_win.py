"""IPv4 и аренда DHCP Wi-Fi адаптера через iphlpapi.GetAdaptersInfo (без прав администратора).

Адаптер ищется по имени вида "{GUID}" - это тот же GUID, что у интерфейса в WLAN API.
LeaseObtained - время получения аренды (time_t, UTC): по нему видно, что DORA завершился и когда.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import POINTER, Structure, byref, c_char, c_int64, c_uint, c_uint32, c_ulong, c_void_p
from typing import Any, Dict, List, Optional

MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8
ERROR_BUFFER_OVERFLOW = 111


class IP_ADDR_STRING(Structure):
    pass


IP_ADDR_STRING._fields_ = [
    ("Next", POINTER(IP_ADDR_STRING)),
    ("IpAddress", c_char * 16),
    ("IpMask", c_char * 16),
    ("Context", c_uint32),
]


class IP_ADAPTER_INFO(Structure):
    pass


IP_ADAPTER_INFO._fields_ = [
    ("Next", POINTER(IP_ADAPTER_INFO)),
    ("ComboIndex", c_uint32),
    ("AdapterName", c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("Description", c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("AddressLength", c_uint),
    ("Address", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("Index", c_uint32),
    ("Type", c_uint),
    ("DhcpEnabled", c_uint),
    ("CurrentIpAddress", c_void_p),
    ("IpAddressList", IP_ADDR_STRING),
    ("GatewayList", IP_ADDR_STRING),
    ("DhcpServer", IP_ADDR_STRING),
    ("HaveWins", ctypes.c_int),
    ("PrimaryWinsServer", IP_ADDR_STRING),
    ("SecondaryWinsServer", IP_ADDR_STRING),
    ("LeaseObtained", c_int64),           # time_t (64 бита на x64)
    ("LeaseExpires", c_int64),
]

EXPECTED_SIZE_X64 = 704


def _s(b: bytes) -> str:
    return b.decode("ascii", "replace").strip("\x00").strip()


def guid_str(g) -> str:
    """GUID из WLAN API в виде {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}."""
    d4 = bytes(g.Data4)
    return "{%08X-%04X-%04X-%s-%s}" % (g.Data1, g.Data2, g.Data3, d4[:2].hex().upper(), d4[2:].hex().upper())


def list_adapters() -> List[Dict[str, Any]]:
    """Все адаптеры (имя-GUID, описание, IPv4) - для проверки раскладки на реальном Windows."""
    out: List[Dict[str, Any]] = []
    if sys.platform != "win32":
        return out
    api = ctypes.windll.iphlpapi
    api.GetAdaptersInfo.argtypes = [c_void_p, POINTER(c_ulong)]
    api.GetAdaptersInfo.restype = c_ulong
    size = c_ulong(0)
    api.GetAdaptersInfo(None, byref(size))
    if not size.value:
        return out
    buf = ctypes.create_string_buffer(size.value)
    if api.GetAdaptersInfo(buf, byref(size)) != 0:
        return out
    p = ctypes.cast(buf, POINTER(IP_ADAPTER_INFO))
    while p:
        a = p.contents
        out.append({"name": _s(a.AdapterName), "description": _s(a.Description), "ip": _s(a.IpAddressList.IpAddress),
                    "dhcp": bool(a.DhcpEnabled), "dhcp_server": _s(a.DhcpServer.IpAddress), "lease": int(a.LeaseObtained)})
        p = a.Next
    return out


def adapter_ip(adapter_guid: str) -> Optional[Dict[str, Any]]:
    """Первый IPv4, шлюз, DHCP-сервер и аренда адаптера; None, если адаптер не найден."""
    if sys.platform != "win32":
        return None
    api = ctypes.windll.iphlpapi
    api.GetAdaptersInfo.argtypes = [c_void_p, POINTER(c_ulong)]
    api.GetAdaptersInfo.restype = c_ulong
    size = c_ulong(0)
    rc = api.GetAdaptersInfo(None, byref(size))
    if rc not in (0, ERROR_BUFFER_OVERFLOW) or not size.value:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if api.GetAdaptersInfo(buf, byref(size)) != 0:
        return None
    p = ctypes.cast(buf, POINTER(IP_ADAPTER_INFO))
    want = adapter_guid.upper()
    while p:
        a = p.contents
        if _s(a.AdapterName).upper() == want:
            dhcp = bool(a.DhcpEnabled)
            return {
                "ip": _s(a.IpAddressList.IpAddress), "mask": _s(a.IpAddressList.IpMask),
                "gateway": _s(a.GatewayList.IpAddress), "dhcp": dhcp,
                "dhcp_server": _s(a.DhcpServer.IpAddress) if dhcp else "",
                "lease_obtained": float(a.LeaseObtained) if dhcp and a.LeaseObtained > 0 else None,
                "lease_expires": float(a.LeaseExpires) if dhcp and a.LeaseExpires > 0 else None,
            }
        p = a.Next
    return None
