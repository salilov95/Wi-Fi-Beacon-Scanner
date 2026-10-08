"""Разбор Information Elements (IE) из beacon / probe response.

Зачем отдельный модуль: сканер Windows отдаёт по каждому BSS просто набор байт
(`ie_raw`). Вся «магия» (RSN, 11k/r/v, HT/VHT/HE, нагрузка канала) - в этих байтах.
Модуль не зависит от Windows и целиком покрывается тестами.

IE устроен просто: [id: 1 байт][длина: 1 байт][данные: длина байт].
Element ID 255 - «расширенный»: первый байт данных - Extension ID.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

OUI_IEEE = b"\x00\x0f\xac"   # 00-0F-AC: наборы шифров/AKM из стандарта 802.11
OUI_MS = b"\x00\x50\xf2"     # 00-50-F2: Microsoft/WFA (WPA1, WMM, WPS)

CIPHERS = {
    1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
    6: "BIP-CMAC-128", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256",
}
AKMS = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
    5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE",
    11: "Suite-B", 12: "Suite-B-192", 13: "FT-802.1X-SHA384", 18: "OWE",
}

# Extension IDs внутри Element ID 255
EXT_HE_CAP = 35
EXT_HE_OP = 36
EXT_EHT_OP = 106   # требует сверки с актуальной редакцией 802.11be
EXT_EHT_CAP = 108  # требует сверки с актуальной редакцией 802.11be


def iter_elements(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Идёт по IE. Обрезанный хвост молча отбрасывается (так бывает в реальных кадрах)."""
    pos = 0
    n = len(data)
    while pos + 2 <= n:
        eid = data[pos]
        ln = data[pos + 1]
        body = data[pos + 2: pos + 2 + ln]
        if len(body) < ln:
            break
        pos += 2 + ln
        yield eid, body


def _suite_name(raw: bytes, table: dict) -> str:
    oui, typ = raw[:3], raw[3]
    if oui in (OUI_IEEE, OUI_MS):
        return table.get(typ, "type%d" % typ)
    return "%s:%d" % (oui.hex("-"), typ)


@dataclass
class Rsn:
    """Содержимое RSN IE (WPA2/WPA3) или WPA1 vendor IE."""
    group: str = "CCMP"
    pairwise: List[str] = field(default_factory=list)
    akm: List[str] = field(default_factory=list)
    mfp_capable: bool = False   # PMF: клиент МОЖЕТ использовать
    mfp_required: bool = False  # PMF: клиент ОБЯЗАН использовать


def parse_rsn_body(b: bytes) -> Optional[Rsn]:
    """b начинается с поля Version (2 байта). Формат у RSN и WPA1 одинаковый."""
    if len(b) < 2:
        return None
    rsn = Rsn()
    pos = 2
    if len(b) >= pos + 4:
        rsn.group = _suite_name(b[pos:pos + 4], CIPHERS)
        pos += 4
    else:
        return rsn
    if len(b) >= pos + 2:
        cnt = int.from_bytes(b[pos:pos + 2], "little")
        pos += 2
        for _ in range(cnt):
            if len(b) < pos + 4:
                return rsn
            rsn.pairwise.append(_suite_name(b[pos:pos + 4], CIPHERS))
            pos += 4
    else:
        return rsn
    if len(b) >= pos + 2:
        cnt = int.from_bytes(b[pos:pos + 2], "little")
        pos += 2
        for _ in range(cnt):
            if len(b) < pos + 4:
                return rsn
            rsn.akm.append(_suite_name(b[pos:pos + 4], AKMS))
            pos += 4
    else:
        return rsn
    if len(b) >= pos + 2:
        caps = int.from_bytes(b[pos:pos + 2], "little")
        rsn.mfp_required = bool(caps & 0x40)  # bit 6 - MFPR
        rsn.mfp_capable = bool(caps & 0x80)   # bit 7 - MFPC
    return rsn


@dataclass
class BssInfo:
    ssid_ie: Optional[bytes] = None
    rates: List[Tuple[float, bool]] = field(default_factory=list)  # (Мбит/с, basic?)
    ds_channel: Optional[int] = None
    dtim_period: Optional[int] = None
    country: Optional[str] = None
    # QBSS Load (IE 11). Не все AP его вещают
    qbss_stations: Optional[int] = None
    qbss_util_pct: Optional[float] = None
    rsn: Optional[Rsn] = None
    wpa1: Optional[Rsn] = None
    wps: bool = False
    wmm: bool = False
    mdid: Optional[int] = None          # Mobility Domain => 802.11r
    ft_over_ds: bool = False
    rm_caps: Optional[bytes] = None     # RM Enabled Capabilities => 802.11k
    bss_transition: bool = False        # Extended Capabilities bit 19 => 802.11v
    ht: bool = False
    ht_primary: Optional[int] = None
    ht_sec_offset: int = 0              # 0 нет, 1 выше, 3 ниже
    ht_width40: bool = False
    ht_protection: int = 0              # 0 none, 1 nonmember, 2 20MHz, 3 non-HT mixed
    ht_streams: int = 0
    vht: bool = False
    vht_width: Optional[int] = None     # 0=20/40, 1=80/160/80+80
    vht_seg0: int = 0
    vht_seg1: int = 0
    vht_streams: int = 0
    he: bool = False
    eht: bool = False
    vendor_ies: List[Tuple[str, int, bytes]] = field(default_factory=list)

    @property
    def dot11k(self) -> bool:
        return self.rm_caps is not None

    @property
    def neighbor_report(self) -> bool:
        return bool(self.rm_caps and self.rm_caps[0] & 0x02)

    @property
    def dot11r(self) -> bool:
        return self.mdid is not None

    @property
    def dot11v(self) -> bool:
        return self.bss_transition

    @property
    def generation(self) -> int:
        """Поколение Wi-Fi по наличию IE: 7/6/5/4, 0 - legacy (a/b/g)."""
        if self.eht:
            return 7
        if self.he:
            return 6
        if self.vht:
            return 5
        if self.ht:
            return 4
        return 0

    @property
    def width_mhz(self) -> int:
        w = 20
        if self.ht and self.ht_width40 and self.ht_sec_offset in (1, 3):
            w = 40
        if self.vht and self.vht_width == 1:
            if self.vht_seg1 == 0:
                w = 80
            elif abs(self.vht_seg1 - self.vht_seg0) == 8:
                w = 160
            else:
                w = 160  # 80+80; для отчёта считаем как 160
        return w

    @property
    def max_streams(self) -> int:
        return max(self.ht_streams, self.vht_streams)


def parse_ies(data: bytes) -> BssInfo:
    info = BssInfo()
    for eid, b in iter_elements(data):
        if eid == 0:
            info.ssid_ie = b
        elif eid in (1, 50):
            for x in b:
                info.rates.append(((x & 0x7F) / 2.0, bool(x & 0x80)))
        elif eid == 3 and b:
            info.ds_channel = b[0]
        elif eid == 5 and len(b) >= 3:
            info.dtim_period = b[1]
        elif eid == 7 and len(b) >= 2:
            info.country = b[:2].decode("ascii", "replace")
        elif eid == 11 and len(b) >= 3:
            info.qbss_stations = int.from_bytes(b[0:2], "little")
            info.qbss_util_pct = round(b[2] * 100.0 / 255.0, 1)
        elif eid == 45 and len(b) >= 7:
            info.ht = True
            for i in range(4):          # Rx MCS bitmask: по байту на пространственный поток
                if b[3 + i]:
                    info.ht_streams = i + 1
        elif eid == 61 and len(b) >= 4:
            info.ht = True
            info.ht_primary = b[0]
            info.ht_sec_offset = b[1] & 0x03
            info.ht_width40 = bool(b[1] & 0x04)
            info.ht_protection = b[2] & 0x03
        elif eid == 48:
            info.rsn = parse_rsn_body(b)
        elif eid == 54 and len(b) >= 3:
            info.mdid = int.from_bytes(b[0:2], "little")
            info.ft_over_ds = bool(b[2] & 0x01)
        elif eid == 70 and len(b) >= 1:
            info.rm_caps = bytes(b)
        elif eid == 127 and len(b) >= 3:
            info.bss_transition = bool((b[2] >> 3) & 1)   # бит 19
        elif eid == 191 and len(b) >= 6:
            info.vht = True
            mcs_map = int.from_bytes(b[4:6], "little")     # Rx VHT-MCS map, 2 бита на поток
            info.vht_streams = sum(1 for i in range(8) if ((mcs_map >> (2 * i)) & 3) != 3)
        elif eid == 192 and len(b) >= 3:
            info.vht = True
            info.vht_width = b[0]
            info.vht_seg0 = b[1]
            info.vht_seg1 = b[2]
        elif eid == 221 and len(b) >= 4:
            oui, typ = bytes(b[:3]), b[3]
            if oui == OUI_MS and typ == 1:
                info.wpa1 = parse_rsn_body(b[4:])
            elif oui == OUI_MS and typ == 2:
                info.wmm = True
            elif oui == OUI_MS and typ == 4:
                info.wps = True
            else:
                info.vendor_ies.append((oui.hex("-"), typ, bytes(b[4:])))
        elif eid == 255 and len(b) >= 1:
            ext = b[0]
            if ext == EXT_HE_CAP or ext == EXT_HE_OP:
                info.he = True
            elif ext == EXT_EHT_CAP or ext == EXT_EHT_OP:
                info.eht = True
    return info


# ---------------------------------------------------------------- расшифровка для показа
IE_NAMES = {
    0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set", 5: "TIM", 7: "Country",
    11: "QBSS Load", 45: "HT Capabilities", 48: "RSN", 50: "Extended Supported Rates",
    54: "Mobility Domain (802.11r)", 61: "HT Operation", 70: "RM Enabled Capabilities (802.11k)",
    127: "Extended Capabilities (802.11v)", 191: "VHT Capabilities", 192: "VHT Operation",
    221: "Vendor Specific", 255: "Extension",
}
EXT_NAMES = {
    35: "HE Capabilities", 36: "HE Operation",
    106: "EHT Operation (ID сверить с 802.11be)", 108: "EHT Capabilities (ID сверить с 802.11be)",
}
MS_TYPES = {1: "WPA (WPA1)", 2: "WMM", 4: "WPS"}
SEC_OFFSET = {0: "нет", 1: "выше", 3: "ниже"}
PROTECTION = {0: "none", 1: "non-member", 2: "20 MHz", 3: "non-HT mixed"}
VHT_WIDTH = {0: "20/40 МГц", 1: "80/160/80+80 МГц", 2: "160 МГц", 3: "80+80 МГц"}
MCS_MAP = {0: "MCS 0-7", 1: "MCS 0-8", 2: "MCS 0-9", 3: "нет"}


def _yn(v) -> str:
    return "да" if v else "нет"


def _ascii(data: bytes) -> str:
    return "".join(chr(x) if 32 <= x < 127 else "." for x in data)


def _decode(eid: int, b: bytes):
    """Возвращает (краткое описание, [(поле, значение), ...])."""
    if eid == 0:
        t = b.decode("utf-8", "replace") or "<скрыт>"
        return t, [("SSID", t)]
    if eid in (1, 50):
        s = " ".join("%g%s" % ((x & 0x7F) / 2.0, "*" if x & 0x80 else "") for x in b) + " Мбит/с"
        return s, [("Скорости (* = basic)", s)]
    if eid == 3 and b:
        return "канал %d" % b[0], [("Канал", str(b[0]))]
    if eid == 5 and len(b) >= 2:
        return "DTIM period %d" % b[1], [("DTIM count", str(b[0])), ("DTIM period", str(b[1]))]
    if eid == 7 and len(b) >= 2:
        cc = b[:2].decode("ascii", "replace")
        return cc, [("Код страны", cc)]
    if eid == 11 and len(b) >= 3:
        st = int.from_bytes(b[0:2], "little")
        u = round(b[2] * 100 / 255.0, 1)
        f = [("Станций", st), ("Загрузка канала", "%s%%" % u)]
        if len(b) >= 5:
            f.append(("Admission capacity", int.from_bytes(b[3:5], "little")))
        return "станций %d, загрузка %s%%" % (st, u), f
    if eid == 45 and len(b) >= 3:
        flags = int.from_bytes(b[0:2], "little")
        streams = 0
        for i in range(4):
            if 3 + i < len(b) and b[3 + i]:
                streams = i + 1
        return "потоков %d" % streams, [
            ("HT Capability Info", "0x%04X" % flags),
            ("Ширина 40 МГц", _yn(flags & 0x02)),
            ("Short GI 20 МГц", _yn(flags & 0x20)),
            ("Short GI 40 МГц", _yn(flags & 0x40)),
            ("Пространственных потоков (Rx)", streams),
        ]
    if eid == 48:
        r = parse_rsn_body(b)
        if r is None:
            return "", [("Данные", b.hex(" "))]
        akm = ", ".join(r.akm) or "—"
        pw = ", ".join(r.pairwise) or "—"
        return "%s; %s" % (akm, pw), [
            ("Групповой шифр", r.group), ("Pairwise", pw), ("AKM", akm),
            ("PMF capable (MFPC)", _yn(r.mfp_capable)), ("PMF required (MFPR)", _yn(r.mfp_required)),
        ]
    if eid == 54 and len(b) >= 3:
        m = int.from_bytes(b[0:2], "little")
        return "MDID 0x%04X" % m, [("MDID", "0x%04X" % m), ("FT over DS", _yn(b[2] & 1))]
    if eid == 61 and len(b) >= 3:
        w40 = bool(b[1] & 4)
        width = "40 МГц" if w40 else "20 МГц"
        return "основной %d, %s" % (b[0], width), [
            ("Основной канал", b[0]), ("Вторичный канал", SEC_OFFSET.get(b[1] & 3, "?")),
            ("Ширина", width), ("HT protection", PROTECTION.get(b[2] & 3, "?")),
        ]
    if eid == 70 and b:
        return "neighbor report " + _yn(b[0] & 2), [("Neighbor report", _yn(b[0] & 2)), ("Сырой байт", "0x%02X" % b[0])]
    if eid == 127 and len(b) >= 3:
        bt = (b[2] >> 3) & 1
        return "BSS Transition: " + _yn(bt), [("BSS Transition (бит 19)", _yn(bt))]
    if eid == 191 and len(b) >= 6:
        mm = int.from_bytes(b[4:6], "little")
        parts = ["%d:%s" % (i + 1, MCS_MAP[(mm >> (2 * i)) & 3]) for i in range(8) if ((mm >> (2 * i)) & 3) != 3]
        return "потоков %d" % len(parts), [
            ("Rx VHT-MCS по потокам", " / ".join(parts) or "нет"),
            ("Пространственных потоков", len(parts)),
        ]
    if eid == 192 and len(b) >= 3:
        w = VHT_WIDTH.get(b[0], "?")
        return "ширина " + w, [("Ширина", w), ("Центр сегмента 0", b[1]), ("Центр сегмента 1", b[2])]
    if eid == 221 and len(b) >= 4:
        oui, typ = b[:3], b[3]
        if oui == OUI_MS:
            name = MS_TYPES.get(typ, "Microsoft type %d" % typ)
            f = [("OUI", "00-50-F2 (Microsoft)"), ("Тип", "%d (%s)" % (typ, name))]
            if typ == 1:
                r = parse_rsn_body(b[4:])
                if r is not None:
                    f += [("AKM", ", ".join(r.akm) or "—"), ("Шифры", ", ".join(r.pairwise) or "—")]
            return name, f
        return "OUI %s, тип %d" % (oui.hex("-"), typ), [
            ("OUI", oui.hex("-")), ("Тип", typ), ("ASCII", _ascii(b[4:])), ("Hex", b[4:].hex(" ")[:120]),
        ]
    if eid == 255 and b:
        name = EXT_NAMES.get(b[0], "расширение %d" % b[0])
        return name, [("Extension ID", b[0]), ("Длина", len(b))]
    return "", [("Данные", b.hex(" ")[:120])]


def describe_ies(data: bytes) -> List[dict]:
    """Список IE в виде, удобном для показа: id, имя, длина, краткое описание, поля, hex."""
    out = []
    for eid, body in iter_elements(data):
        try:
            summary, fields = _decode(eid, body)
        except Exception as e:  # noqa: BLE001 - битый IE не должен ронять весь разбор
            summary, fields = "ошибка разбора: %s" % e, []
        out.append({
            "id": eid,
            "name": IE_NAMES.get(eid, "Element %d" % eid),
            "len": len(body),
            "summary": summary,
            "fields": [[k, str(v)] for k, v in fields],
            "hex": body.hex(" "),
        })
    return out
