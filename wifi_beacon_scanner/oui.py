"""Определение вендора по BSSID с помощью файла manuf из Wireshark.

Формат строк manuf:
    00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc          (блок /24)
    70:B3:D5:FF:F0:00/36<TAB>Short<TAB>Long name       (блок /36, /28 и т.д.)
Ищем самое длинное совпадение префикса.
"""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

DEFAULT_PATHS = [
    os.path.join(os.path.dirname(__file__), "data", "manuf"),
    r"C:\Program Files\Wireshark\manuf",
    r"C:\Program Files (x86)\Helge Keck\WinFi\vendors.txt",
]


class OuiDb:
    def __init__(self) -> None:
        # bits -> {значение префикса: имя}
        self._by_bits: Dict[int, Dict[int, str]] = {}

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_bits.values())

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                cols = line.rstrip("\n").split("\t")
                if len(cols) < 2:
                    continue
                prefix = cols[0].strip()
                name = (cols[2] if len(cols) > 2 and cols[2].strip() else cols[1]).strip()
                bits = 24
                if "/" in prefix:
                    prefix, b = prefix.split("/", 1)
                    try:
                        bits = int(b)
                    except ValueError:
                        continue
                try:
                    octets = bytes.fromhex(prefix.replace(":", "").replace("-", ""))
                except ValueError:
                    continue
                val = int.from_bytes(octets, "big")
                total = len(octets) * 8
                if total < bits:  # маска длиннее записанного префикса - пропускаем
                    continue
                val >>= (total - bits)
                self._by_bits.setdefault(bits, {})[val] = name

    def lookup(self, bssid: str) -> Optional[str]:
        raw = int(bssid.replace(":", "").replace("-", ""), 16)
        for bits in sorted(self._by_bits, reverse=True):
            key = raw >> (48 - bits)
            hit = self._by_bits[bits].get(key)
            if hit:
                return hit
        return None


def load_default(explicit: Optional[str] = None) -> Optional[OuiDb]:
    """Возвращает базу или None, если ни один файл не найден."""
    candidates: List[str] = [explicit] if explicit else DEFAULT_PATHS
    for p in candidates:
        if p and os.path.isfile(p):
            db = OuiDb()
            db.load(p)
            return db
    return None
