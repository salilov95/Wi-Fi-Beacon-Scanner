"""Сравнение двух снапшотов: «до» (базовый) и «после» (текущий).

Зачем: после правки на контроллере видно, что реально изменилось в эфире - появились/пропали
BSS, сменился канал, ширина, безопасность, включился 802.11r и т.п. RSSI меняется всегда,
поэтому он вынесен отдельно и показывается только при заметной разнице.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Sequence, Tuple

from .model import Bss


def _pmf(b: Bss) -> str:
    r = b.info.rsn
    if r is None:
        return "-"
    return "required" if r.mfp_required else "capable" if r.mfp_capable else "no"


def _yn(v: bool) -> str:
    return "да" if v else "нет"


FIELDS: List[Tuple[str, Callable[[Bss], Any]]] = [
    ("SSID", lambda b: b.ssid_display),
    ("Канал", lambda b: b.channel),
    ("Ширина, МГц", lambda b: b.info.width_mhz),
    ("Безопасность", lambda b: b.security),
    ("Шифры", lambda b: "/".join(b.ciphers) or "-"),
    ("PMF", _pmf),
    ("802.11k", lambda b: _yn(b.info.dot11k)),
    ("802.11r", lambda b: _yn(b.info.dot11r)),
    ("802.11v", lambda b: _yn(b.info.dot11v)),
    ("Поколение", lambda b: b.generation_label),
    ("Страна", lambda b: b.info.country or "-"),
    ("Beacon interval", lambda b: b.beacon_interval),
]


def _brief(b: Bss) -> Dict[str, Any]:
    return {"bssid": b.bssid, "ssid": b.ssid_display, "band": b.band, "channel": b.channel,
            "rssi": b.rssi, "security": b.security}


def diff_snapshots(old: Sequence[Bss], new: Sequence[Bss], rssi_delta: int = 8) -> Dict[str, Any]:
    o = {b.bssid: b for b in old}
    n = {b.bssid: b for b in new}
    added = [_brief(n[k]) for k in sorted(n.keys() - o.keys())]
    removed = [_brief(o[k]) for k in sorted(o.keys() - n.keys())]
    changed, rssi = [], []
    for k in sorted(o.keys() & n.keys()):
        a, b = o[k], n[k]
        ch = []
        for name, fn in FIELDS:
            x, y = fn(a), fn(b)
            if x != y:
                ch.append({"field": name, "old": str(x), "new": str(y)})
        if ch:
            changed.append({"bssid": k, "ssid": b.ssid_display, "changes": ch})
        if abs(b.rssi - a.rssi) >= rssi_delta:
            rssi.append({"bssid": k, "ssid": b.ssid_display, "old": a.rssi, "new": b.rssi, "delta": b.rssi - a.rssi})
    rssi.sort(key=lambda r: r["delta"])
    return {"added": added, "removed": removed, "changed": changed, "rssi": rssi, "rssi_delta": rssi_delta,
            "same": len(o.keys() & n.keys()) - len(changed)}
