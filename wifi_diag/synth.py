"""Сборка синтетических IE (для тестов и демо-режима). Байты собраны по описанию стандарта
802.11 и не используют parser-код, поэтому тест проверяет парсер, а не сам себя."""
from __future__ import annotations

import struct
from typing import Iterable, Optional

from wifi_diag.model import Bss


def ie(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body


def ssid_ie(name: str) -> bytes:
    return ie(0, name.encode())


def rates_ie(rates_mbps: Iterable[float], basic: Iterable[float] = ()) -> bytes:
    basic = set(basic)
    return ie(1, bytes(int(r * 2) | (0x80 if r in basic else 0) for r in rates_mbps))


def ds_ie(ch: int) -> bytes:
    return ie(3, bytes([ch]))


def tim_ie(dtim_period: int = 1) -> bytes:
    return ie(5, bytes([0, dtim_period, 0, 0]))


def country_ie(cc: str = "RU") -> bytes:
    return ie(7, cc.encode() + b" " + bytes([1, 13, 20]))


def qbss_ie(stations: int, util_255: int) -> bytes:
    return ie(11, struct.pack("<HBH", stations, util_255, 0))


def suite(oui: bytes, typ: int) -> bytes:
    return oui + bytes([typ])


IEEE = b"\x00\x0f\xac"


def rsn_ie(akms: Iterable[int], pairwise: Iterable[int] = (4,), group: int = 4, mfpc: bool = False,
           mfpr: bool = False) -> bytes:
    akms, pairwise = list(akms), list(pairwise)
    caps = (0x80 if mfpc else 0) | (0x40 if mfpr else 0)
    body = struct.pack("<H", 1) + suite(IEEE, group)
    body += struct.pack("<H", len(pairwise)) + b"".join(suite(IEEE, p) for p in pairwise)
    body += struct.pack("<H", len(akms)) + b"".join(suite(IEEE, a) for a in akms)
    body += struct.pack("<H", caps)
    return ie(48, body)


def wpa1_ie(akm: int = 2, cipher: int = 2) -> bytes:
    ms = b"\x00\x50\xf2"
    body = ms + b"\x01" + struct.pack("<H", 1) + suite(ms, cipher)
    body += struct.pack("<H", 1) + suite(ms, cipher) + struct.pack("<H", 1) + suite(ms, akm)
    return ie(221, body)


def mobility_domain_ie(mdid: int = 0x1234, ft_over_ds: bool = True) -> bytes:
    return ie(54, struct.pack("<HB", mdid, 1 if ft_over_ds else 0))


def rm_caps_ie(neighbor_report: bool = True) -> bytes:
    return ie(70, bytes([0x02 if neighbor_report else 0x00, 0, 0, 0, 0]))


def ext_caps_ie(bss_transition: bool = True) -> bytes:
    b = bytearray(8)
    if bss_transition:
        b[2] |= 1 << 3     # бит 19 = byte 2, bit 3
    return ie(127, bytes(b))


def ht_cap_ie(streams: int = 2) -> bytes:
    mcs = bytes([0xFF] * streams + [0] * (16 - streams))
    return ie(45, struct.pack("<HB", 0x01EF, 0x17) + mcs + b"\x00" * 10)


def ht_op_ie(primary: int, width40: bool = False, sec_offset: int = 0, protection: int = 0) -> bytes:
    b1 = (sec_offset & 3) | (0x04 if width40 else 0)
    return ie(61, bytes([primary, b1, protection & 3, 0, 0]) + b"\x00" * 16)


def vht_cap_ie(streams: int = 2) -> bytes:
    mcs_map = 0
    for i in range(8):
        mcs_map |= (2 if i < streams else 3) << (2 * i)
    return ie(191, struct.pack("<IHHHH", 0x0F8259B2, mcs_map, 0, mcs_map, 0))


def vht_op_ie(width: int, seg0: int, seg1: int = 0) -> bytes:
    return ie(192, bytes([width, seg0, seg1, 0, 0]))


def he_cap_ie() -> bytes:
    return ie(255, bytes([35]) + b"\x00" * 20)


def vendor_ie(oui: bytes, typ: int, data: bytes = b"") -> bytes:
    return ie(221, oui + bytes([typ]) + data)


def make_bss(bssid: str, ssid: str, freq_khz: int, rssi: int, ies: bytes, capability: int = 0x0411,
             beacon: int = 100) -> Bss:
    return Bss(bssid=bssid, ssid_bytes=ssid.encode(), rssi=rssi, link_quality=60, freq_khz=freq_khz,
               beacon_interval=beacon, capability=capability, phy_type=7, ie_raw=ssid_ie(ssid) + ies)


CH1, CH6, CH11 = 2_412_000, 2_437_000, 2_462_000
CH36, CH100 = 5_180_000, 5_500_000
