"""Модель одного BSS (одна точка доступа на одном радио) и снапшот скана."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .ie import BssInfo, parse_ies

SNAPSHOT_VERSION = 1


def freq_to_band(freq_khz: int) -> str:
    if freq_khz < 3_000_000:
        return "2.4"
    if freq_khz < 5_925_000:
        return "5"
    return "6"


def freq_to_channel(freq_khz: int) -> int:
    if freq_khz == 2_484_000:
        return 14
    band = freq_to_band(freq_khz)
    if band == "2.4":
        return (freq_khz - 2_407_000) // 5000
    if band == "5":
        return (freq_khz - 5_000_000) // 5000
    return (freq_khz - 5_950_000) // 5000


@dataclass
class Bss:
    bssid: str                 # "aa:bb:cc:dd:ee:ff"
    ssid_bytes: bytes
    rssi: int                  # dBm
    link_quality: int          # 0..100, оценка драйвера
    freq_khz: int
    beacon_interval: int       # TU (1 TU = 1024 мкс)
    capability: int
    phy_type: int
    ie_raw: bytes
    vendor: Optional[str] = None   # заполняется из OUI-базы
    info: BssInfo = field(init=False)

    def __post_init__(self) -> None:
        self.info = parse_ies(self.ie_raw)

    # --- удобные производные поля ---
    @property
    def hidden(self) -> bool:
        return len(self.ssid_bytes) == 0 or all(x == 0 for x in self.ssid_bytes)

    @property
    def ssid(self) -> str:
        return "" if self.hidden else self.ssid_bytes.decode("utf-8", "replace")

    @property
    def ssid_display(self) -> str:
        return "<hidden>" if self.hidden else self.ssid

    @property
    def band(self) -> str:
        return freq_to_band(self.freq_khz)

    @property
    def channel(self) -> int:
        return freq_to_channel(self.freq_khz)

    @property
    def center_channel(self) -> float:
        """Центр занимаемой полосы в номерах каналов (для графика). Для 20 МГц = основной канал."""
        i = self.info
        w = i.width_mhz
        if w >= 160 and i.vht_seg1 and abs(i.vht_seg1 - i.vht_seg0) == 8:
            return float(i.vht_seg1)
        if w >= 80 and i.vht_seg0:
            return float(i.vht_seg0)
        if w == 40:
            return float(self.channel + (2 if i.ht_sec_offset == 1 else -2))
        return float(self.channel)

    @property
    def locally_administered(self) -> bool:
        return bool(int(self.bssid[:2], 16) & 0x02)

    @property
    def privacy_bit(self) -> bool:
        return bool(self.capability & 0x0010)

    @property
    def security(self) -> str:
        i = self.info
        if i.rsn is not None:
            akm = set(i.rsn.akm)
            ent = {"802.1X", "FT-802.1X", "802.1X-SHA256", "Suite-B", "Suite-B-192", "FT-802.1X-SHA384"}
            parts = []
            if akm & {"Suite-B-192", "FT-802.1X-SHA384"}:
                parts.append("WPA3-Enterprise 192")
            elif akm & ent:
                parts.append("WPA2/3-Enterprise" if i.rsn.mfp_required else "WPA2-Enterprise")
            if "SAE" in akm or "FT-SAE" in akm:
                if akm & {"PSK", "FT-PSK", "PSK-SHA256"}:
                    parts.append("WPA2/WPA3-Personal")
                else:
                    parts.append("WPA3-Personal")
            elif akm & {"PSK", "FT-PSK", "PSK-SHA256"}:
                parts.append("WPA2-Personal")
            if "OWE" in akm:
                parts.append("OWE")
            label = "+".join(parts) if parts else "RSN(" + ",".join(sorted(akm)) + ")"
            if i.wpa1 is not None:
                label += "+WPA1"
            return label
        if i.wpa1 is not None:
            return "WPA1-Enterprise" if "802.1X" in i.wpa1.akm else "WPA1-Personal"
        return "WEP" if self.privacy_bit else "Open"

    @property
    def ciphers(self) -> List[str]:
        out: List[str] = []
        for r in (self.info.rsn, self.info.wpa1):
            if r is not None:
                for c in r.pairwise:
                    if c not in out:
                        out.append(c)
        return out

    @property
    def generation_label(self) -> str:
        g = self.info.generation
        if g == 0:
            return "legacy"
        if g == 6 and self.band == "6":
            return "Wi-Fi 6E"
        return "Wi-Fi %d" % g


@dataclass
class Snapshot:
    taken_at: str
    interface: str
    bss: List[Bss]

    def to_json(self) -> str:
        data = {
            "version": SNAPSHOT_VERSION,
            "taken_at": self.taken_at,
            "interface": self.interface,
            "bss": [
                {
                    "bssid": b.bssid,
                    "ssid_hex": b.ssid_bytes.hex(),
                    "rssi": b.rssi,
                    "link_quality": b.link_quality,
                    "freq_khz": b.freq_khz,
                    "beacon_interval": b.beacon_interval,
                    "capability": b.capability,
                    "phy_type": b.phy_type,
                    "ie_hex": b.ie_raw.hex(),
                }
                for b in self.bss
            ],
        }
        return json.dumps(data, ensure_ascii=False, indent=1)

    @staticmethod
    def from_json(text: str) -> "Snapshot":
        d = json.loads(text)
        if d.get("version") != SNAPSHOT_VERSION:
            raise ValueError("неподдерживаемая версия снапшота: %r" % d.get("version"))
        bss = [
            Bss(
                bssid=x["bssid"],
                ssid_bytes=bytes.fromhex(x["ssid_hex"]),
                rssi=x["rssi"],
                link_quality=x["link_quality"],
                freq_khz=x["freq_khz"],
                beacon_interval=x["beacon_interval"],
                capability=x["capability"],
                phy_type=x["phy_type"],
                ie_raw=bytes.fromhex(x["ie_hex"]),
            )
            for x in d["bss"]
        ]
        return Snapshot(d["taken_at"], d.get("interface", ""), bss)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
