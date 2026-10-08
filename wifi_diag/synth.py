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


def ht_op_ie(primary: int, width40: bool = False, sec_offset: int = 0, protection: int = 0,
             basic_mcs: int = 0) -> bytes:
    b1 = (sec_offset & 3) | (0x04 if width40 else 0)
    return ie(61, bytes([primary, b1, protection & 3, 0, 0, 0]) + struct.pack("<I", basic_mcs) + b"\x00" * 12)


def vht_cap_ie(streams: int = 2, val: int = 2, caps: int = 0x0F8259B2) -> bytes:
    m = mcs_map(streams, val)
    return ie(191, struct.pack("<IHHHH", caps, m, 0, m, 0))


def vht_op_ie(width: int, seg0: int, seg1: int = 0, basic: int = 0xFFFC) -> bytes:
    return ie(192, bytes([width, seg0, seg1]) + struct.pack("<H", basic))


def mcs_map(streams: int, val: int) -> int:
    """MCS map VHT/HE: val на первые streams потоков, остальные 3 (не поддержан)."""
    m = 0
    for i in range(8):
        m |= (val if i < streams else 3) << (2 * i)
    return m


def he_cap_ie(streams: int = 2, val: int = 2, w160: bool = False) -> bytes:
    """HE Capabilities: MAC caps (6), PHY caps (11), HE-MCS map <=80 (Rx, Tx), при w160 ещё карты для 160.
    val: 0 = MCS 0-7, 1 = 0-9, 2 = 0-11."""
    phy = bytearray(11)
    phy[0] = 0x02 | 0x04 | (0x08 if w160 else 0)      # Channel Width Set: 40 в 2.4, 40/80 в 5, 160 в 5
    m = mcs_map(streams, val)
    maps = struct.pack("<HH", m, m) + (struct.pack("<HH", m, m) if w160 else b"")
    return ie(255, bytes([35]) + b"\x00" * 6 + bytes(phy) + maps)


def he_op_ie(color: int = 5, basic: int = 0xFFFC, six: Optional[tuple] = None) -> bytes:
    """HE Operation. six = (primary, width_code, ccfs0, ccfs1) добавляет 6 GHz Operation Information."""
    params = (1 << 17) if six else 0
    body = bytes([36]) + params.to_bytes(3, "little") + bytes([color & 0x3F]) + struct.pack("<H", basic)
    if six:
        p, w, c0, c1 = six
        body += bytes([p, w & 3, c0, c1, 6])
    return ie(255, body)


def vendor_ie(oui: bytes, typ: int, data: bytes = b"") -> bytes:
    return ie(221, oui + bytes([typ]) + data)


def make_bss(bssid: str, ssid: str, freq_khz: int, rssi: int, ies: bytes, capability: int = 0x0411,
             beacon: int = 100) -> Bss:
    return Bss(bssid=bssid, ssid_bytes=ssid.encode(), rssi=rssi, link_quality=60, freq_khz=freq_khz,
               beacon_interval=beacon, capability=capability, phy_type=7, ie_raw=ssid_ie(ssid) + ies)


CH1, CH6, CH11 = 2_412_000, 2_437_000, 2_462_000
CH36, CH100 = 5_180_000, 5_500_000
