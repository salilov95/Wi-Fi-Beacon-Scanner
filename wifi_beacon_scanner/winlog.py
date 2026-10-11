"""Журнал Windows Microsoft-Windows-WLAN-AutoConfig/Operational: история подключений с причинами.

Чтение - через wevtapi (EvtQuery / EvtNext / EvtRender / EvtFormatMessage) в winlog_win.py; здесь
разбор XML события и группировка по стадиям, без привязки к Windows. Текст события берётся из самой
Windows (EvtFormatMessage), поэтому номера событий ниже нужны только для группировки и цвета.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Optional

CHANNEL = "Microsoft-Windows-WLAN-AutoConfig/Operational"
PUBLISHER = "Microsoft-Windows-WLAN-AutoConfig"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# группы по номерам событий (известные мне диапазоны; остальные - «прочее»)
GROUPS = [
    (8000, 8003, "подключение"),
    (11000, 11002, "ассоциация"),
    (11004, 11010, "безопасность / 4-way"),
    (12011, 12013, "802.1X"),
]
LEVEL_RU = {1: "критично", 2: "ошибка", 3: "предупреждение", 4: "информация", 0: "информация", 5: "подробно"}


def group_of(event_id: int) -> str:
    for a, b, name in GROUPS:
        if a <= event_id <= b:
            return name
    return "прочее"


def _time(s: str) -> Optional[float]:
    if not s:
        return None
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = head + "." + frac[:6]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            from datetime import timezone
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def parse_event_xml(xml: str, message: str = "") -> Dict[str, Any]:
    root = ET.fromstring(xml)
    sysn = root.find("e:System", NS)
    eid = int((sysn.findtext("e:EventID", "0", NS) if sysn is not None else "0") or 0)
    level = int((sysn.findtext("e:Level", "0", NS) if sysn is not None else "0") or 0)
    tc = sysn.find("e:TimeCreated", NS) if sysn is not None else None
    data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for d in ed.findall("e:Data", NS):
            name = d.get("Name") or "Data%d" % len(data)
            data[name] = (d.text or "").strip()
    return {
        "t": _time(tc.get("SystemTime", "") if tc is not None else ""),
        "id": eid, "level": level, "level_ru": LEVEL_RU.get(level, str(level)),
        "group": group_of(eid), "message": message.strip(),
        "ssid": data.get("SSID", ""), "bssid": data.get("BSSID", data.get("PeerMac", "")),
        "reason": data.get("Reason", data.get("FailureReason", "")),
        "data": data,
    }
