"""Какие дополнения 802.11 объявляет точка доступа: d, e, h, i, k, r, u, v, w и несколько функций сверх них.

Всё берётся из beacon / probe response: поле Capability Information и Information Elements.
Это объявленные возможности, а не проверка того, что они реально работают.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from .i18n import N_, tr
from .ie import ACCESS_NETWORK_TYPE, BssInfo
from .model import Bss

# Capability Information (802.11-2020, 9.4.1.4)
CAP_SPECTRUM_MGMT = 1 << 8      # 802.11h
CAP_QOS = 1 << 9                # 802.11e
CAP_RADIO_MEASUREMENT = 1 << 12  # 802.11k

# код, подпись в таблице, полное название
STANDARDS: List[Tuple[str, str, str]] = [
    ("d", "d", N_("802.11d - код страны и разрешённые каналы")),
    ("e", "e", "802.11e - QoS (WMM / EDCA)"),
    ("h", "h", N_("802.11h - DFS/TPC: управление спектром и мощностью")),
    ("i", "i", "802.11i - RSN (WPA2/WPA3)"),
    ("k", "k", "802.11k - Radio Measurement, neighbor report"),
    ("r", "r", "802.11r - Fast BSS Transition (FT)"),
    ("u", "u", "802.11u - Interworking"),
    ("v", "v", "802.11v - BSS Transition Management"),
    ("w", "w", N_("802.11w - PMF, защита management-кадров")),
    ("mc", "mc", N_("802.11mc - FTM, измерение расстояния (RTT)")),
    ("ai", "ai", N_("802.11ai - FILS, быстрая первичная аутентификация")),
    ("s", "s", "802.11s - mesh"),
    ("twt", "TWT", "TWT - Target Wake Time (802.11ax)"),
    ("mbssid", "MBSSID", N_("Multiple BSSID: несколько SSID в одном beacon")),
    ("hs", "HS2.0", "Hotspot 2.0 / Passpoint"),
]
CODES = [c for c, _, _ in STANDARDS]
LABEL = {c: lab for c, lab, _ in STANDARDS}
TITLE = {c: t for c, _, t in STANDARDS}


def _d(b: Bss, i: BssInfo) -> Optional[str]:
    return tr("страна %s") % i.country if i.country else None


def _e(b: Bss, i: BssInfo) -> Optional[str]:
    parts = [x for x, on in (("WMM", i.wmm), ("EDCA", i.edca), (tr("QoS в Capability"), b.capability & CAP_QOS)) if on]
    return ", ".join(parts) or None


def _h(b: Bss, i: BssInfo) -> Optional[str]:
    parts = []
    if b.capability & CAP_SPECTRUM_MGMT:
        parts.append("Spectrum Management")
    if i.power_constraint is not None:
        parts.append(tr("Power Constraint %d дБ") % i.power_constraint)
    if i.tpc_tx_power is not None:
        parts.append(tr("TPC Report %d дБм") % i.tpc_tx_power)
    if i.csa:
        parts.append(tr("объявлена смена канала (CSA)"))
    return ", ".join(parts) or None


def _i(b: Bss, i: BssInfo) -> Optional[str]:
    return ", ".join(i.rsn.akm) or "RSN" if i.rsn else None


def _k(b: Bss, i: BssInfo) -> Optional[str]:
    if not i.dot11k:
        return None
    return "neighbor report" if i.neighbor_report else tr("без neighbor report")


def _r(b: Bss, i: BssInfo) -> Optional[str]:
    if i.mdid is None:
        return None
    return "MDID 0x%04X%s" % (i.mdid, ", FT over DS" if i.ft_over_ds else "")


def _u(b: Bss, i: BssInfo) -> Optional[str]:
    if i.interworking is None and not i.ext_bit(31):
        return None
    parts = []
    if i.interworking is not None:
        parts.append(tr(ACCESS_NETWORK_TYPE.get(i.interworking & 0x0F, "")) or tr("тип %d") % (i.interworking & 0x0F))
        if i.interworking & 0x10:
            parts.append(tr("интернет"))
    if i.anqp:
        parts.append("ANQP")
    if i.roaming_consortium:
        parts.append("Roaming Consortium")
    return ", ".join(parts) or "Interworking"


V_EXTRA = ((12, "Proxy ARP"), (17, "WNM Sleep"), (16, "TFS"), (26, "DMS"), (18, "TIM Broadcast"), (46, "WNM Notification"))


def _v(b: Bss, i: BssInfo) -> Optional[str]:
    if not i.dot11v:
        return None
    extra = [name for bit, name in V_EXTRA if i.ext_bit(bit)]
    return "BTM" + (", " + ", ".join(extra) if extra else "")


def _w(b: Bss, i: BssInfo) -> Optional[str]:
    if not i.rsn or not (i.rsn.mfp_capable or i.rsn.mfp_required):
        return None
    return tr("обязательна") if i.rsn.mfp_required else tr("поддерживается")


def _mc(b: Bss, i: BssInfo) -> Optional[str]:
    parts = [x for x, on in (("responder", i.ext_bit(70)), ("initiator", i.ext_bit(71))) if on]
    return "FTM " + ", ".join(parts) if parts else None


def _ai(b: Bss, i: BssInfo) -> Optional[str]:
    return "FILS" if i.ext_bit(72) else None


def _s(b: Bss, i: BssInfo) -> Optional[str]:
    if i.mesh_id is None:
        return None
    return "Mesh ID %s" % (i.mesh_id.decode("utf-8", "replace") or tr("(пусто)"))


def _twt(b: Bss, i: BssInfo) -> Optional[str]:
    return "TWT responder" if i.twt_responder else None


def _mbssid(b: Bss, i: BssInfo) -> Optional[str]:
    return "Multiple BSSID" if i.multi_bssid or i.ext_bit(22) else None


def _hs(b: Bss, i: BssInfo) -> Optional[str]:
    return "Passpoint" if i.hs20 else None


_FN: Dict[str, Callable[[Bss, BssInfo], Optional[str]]] = {
    "d": _d, "e": _e, "h": _h, "i": _i, "k": _k, "r": _r, "u": _u, "v": _v, "w": _w,
    "mc": _mc, "ai": _ai, "s": _s, "twt": _twt, "mbssid": _mbssid, "hs": _hs,
}


def standards(b: Bss) -> Dict[str, str]:
    """{код: пояснение} только для объявленных точкой дополнений, в порядке STANDARDS."""
    out: Dict[str, str] = {}
    for c in CODES:
        v = _FN[c](b, b.info)
        if v:
            out[c] = v
    return out


def short(std: Dict[str, str]) -> str:
    """Строка для CSV и отчётов: «d e h i k r v w TWT»."""
    return " ".join(LABEL[c] for c in CODES if c in std)
