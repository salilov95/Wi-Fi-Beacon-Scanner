"""MCS и PHY-скорости 802.11n/ac/ax.

Beacon несёт не «текущий MCS», а то, что AP умеет: набор MCS на каждый пространственный поток
(HT Capabilities, VHT Capabilities, HE Capabilities) и обязательный минимум (Basic MCS Set в
HT/VHT/HE Operation). Реальный MCS кадра виден только в monitor mode (radiotap), Native Wifi API
его не отдаёт. Для собственного подключения Windows сообщает скорость приёма/передачи,
по ней MCS можно оценить (rate_to_mcs).

Скорость считается по формуле стандарта: N_SD * N_BPSCS * R * N_SS / T_SYM.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .ie import BssInfo, map_streams

# (бит на поднесущую, кодовая скорость) для MCS 0..13; одинаково для VHT и HE, для HT - MCS по модулю 8
MOD = [(1, 1 / 2), (2, 1 / 2), (2, 3 / 4), (4, 1 / 2), (4, 3 / 4), (6, 2 / 3), (6, 3 / 4), (6, 5 / 6),
       (8, 3 / 4), (8, 5 / 6), (10, 3 / 4), (10, 5 / 6), (12, 3 / 4), (12, 5 / 6)]
MOD_NAME = ["BPSK 1/2", "QPSK 1/2", "QPSK 3/4", "16-QAM 1/2", "16-QAM 3/4", "64-QAM 2/3", "64-QAM 3/4",
            "64-QAM 5/6", "256-QAM 3/4", "256-QAM 5/6", "1024-QAM 3/4", "1024-QAM 5/6", "4096-QAM 3/4",
            "4096-QAM 5/6"]
# число поднесущих данных по ширине канала
NSD = {
    "HT": {20: 52, 40: 108},
    "VHT": {20: 52, 40: 108, 80: 234, 160: 468},
    "HE": {20: 234, 40: 468, 80: 980, 160: 1960},
}
MAX_MCS = {"HT": 7, "VHT": 9, "HE": 11}
GI = {"HT": (0.4, 0.8), "VHT": (0.4, 0.8), "HE": (0.8, 1.6, 3.2)}
PHY_ORDER = ["HT", "VHT", "HE"]
PHY_GEN = {"HT": 4, "VHT": 5, "HE": 6}
# максимум MCS по 2-битному значению карты
VHT_MAP_MAX = {0: 7, 1: 8, 2: 9}
HE_MAP_MAX = {0: 7, 1: 9, 2: 11}
LEGACY_RATES = (1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0)


def vht_valid(mcs: int, nss: int, width: int) -> bool:
    """В VHT несколько сочетаний MCS/NSS/ширины запрещены стандартом (не делится число бит на символ)."""
    if width == 20 and mcs == 9 and nss not in (3, 6):
        return False
    if width == 80 and ((mcs == 6 and nss in (3, 7)) or (mcs == 9 and nss == 6)):
        return False
    if width == 160 and mcs == 9 and nss == 3:
        return False
    return True


def phy_rate(phy: str, mcs: int, nss: int, width: int, gi: Optional[float] = None) -> Optional[float]:
    """Скорость в Мбит/с. mcs для HT - индекс внутри потока (0..7); gi в мкс, по умолчанию самый короткий."""
    nsd = NSD.get(phy, {}).get(width)
    if nsd is None or not 0 <= mcs <= MAX_MCS[phy] or nss < 1:
        return None
    if gi is None:
        gi = GI[phy][0]
    tsym = (12.8 if phy == "HE" else 3.2) + gi
    bits, r = MOD[mcs]
    return nsd * bits * r * nss / tsym


def _map_max(m: int, table: Dict[int, int]) -> Optional[int]:
    vals = [table[(m >> (2 * i)) & 3] for i in range(8) if ((m >> (2 * i)) & 3) != 3]
    return max(vals) if vals else None


def map_text(m: Optional[int], table: Dict[int, int]) -> str:
    """'MCS 0-9 x2' если все потоки одинаковы, иначе по потокам."""
    if m is None:
        return ""
    per = [table[(m >> (2 * i)) & 3] for i in range(8) if ((m >> (2 * i)) & 3) != 3]
    if not per:
        return "нет"
    if len(set(per)) == 1:
        return "MCS 0-%d, потоков %d" % (per[0], len(per))
    return ", ".join("поток %d: MCS 0-%d" % (i + 1, v) for i, v in enumerate(per))


def ht_mask_text(mask: Optional[int]) -> str:
    if mask is None:
        return ""
    idx = [i for i in range(32) if mask >> i & 1]
    if not idx:
        return "нет"
    # сжатие в диапазоны: 0-7, 8-15
    out, start = [], idx[0]
    for a, b in zip(idx, idx[1:] + [None]):
        if b != a + 1:
            out.append(str(start) if start == a else "%d-%d" % (start, a))
            start = b
    return "MCS " + ", ".join(out)


def _sgi(info: BssInfo, width: int) -> bool:
    return {20: info.ht_sgi20, 40: info.ht_sgi40, 80: info.vht_sgi80, 160: info.vht_sgi160}.get(width, False)


def capability(info: BssInfo) -> Dict[str, Any]:
    """Что умеет AP по beacon: стандарт, потоки, старший MCS и максимальная PHY-скорость на рабочей ширине.

    Скорость - теоретический потолок канального уровня при лучшем сигнале и клиенте с тем же числом
    потоков; реальная пропускная способность заметно ниже.
    """
    width = info.width_mhz
    out: Dict[str, Any] = {"phy": "legacy", "nss": 1, "mcs": None, "width": width, "gi": None, "rate": None,
                           "label": "", "eht_note": info.eht}
    if info.he and info.he_rx80 is not None and map_streams(info.he_rx80):
        m = info.he_rx160 if width >= 160 and info.he_rx160 is not None else info.he_rx80
        if width >= 160 and info.he_rx160 is None:
            width = 80
        nss, mcs = map_streams(m), _map_max(m, HE_MAP_MAX)
        phy, gi = "HE", 0.8
    elif info.vht and info.vht_rx_map is not None and map_streams(info.vht_rx_map):
        nss, mcs = map_streams(info.vht_rx_map), _map_max(info.vht_rx_map, VHT_MAP_MAX)
        phy = "VHT"
        while mcs is not None and mcs > 0 and not vht_valid(mcs, nss, width):
            mcs -= 1
        gi = 0.4 if _sgi(info, width) else 0.8
    elif info.ht and info.ht_mcs_max is not None:
        width = min(width, 40)
        phy, nss, mcs = "HT", info.ht_mcs_max // 8 + 1, info.ht_mcs_max % 8
        gi = 0.4 if _sgi(info, width) else 0.8
    else:
        rates = [r for r, _ in info.rates]
        out["rate"] = max(rates) if rates else None
        out["label"] = "legacy"
        return out
    out.update(phy=phy, nss=nss, mcs=mcs, width=width, gi=gi, rate=phy_rate(phy, mcs, nss, width, gi))
    out["label"] = "%s MCS %d x%d" % (phy, mcs, nss)
    return out


def rate_to_mcs(rate_mbps: Optional[float], max_phy: str = "HE", width_max: int = 160,
                band: str = "5", limit: int = 3, max_nss: int = 4, likely_nss: int = 2) -> List[Dict[str, Any]]:
    """Какие MCS/NSS/ширина/GI дают такую скорость. Windows отдаёт скорость с округлением, поэтому допуск
    0.6 Мбит/с плюс 0.1%. Совпадений бывает несколько (например, MCS 4 x3 и MCS 8 x1 дают почти одно и то же).
    Порядок: стандарт и ширина BSS, затем likely_nss потоков (у ноутбуков почти всегда 2x2), затем короткий GI.
    Потоков не больше, чем у AP (max_nss)."""
    if not rate_mbps or rate_mbps <= 0:
        return []
    tol = 0.6 + rate_mbps * 0.001
    phys = PHY_ORDER[:PHY_ORDER.index(max_phy) + 1] if max_phy in PHY_ORDER else []
    if band == "2.4":
        phys = [p for p in phys if p != "VHT"]
    elif band == "6":
        phys = [p for p in phys if p == "HE"]
    found: List[Dict[str, Any]] = []
    for phy in phys:
        for width in NSD[phy]:
            if width > width_max:
                continue
            for nss in range(1, max(1, min(4, max_nss)) + 1):
                for mcs in range(MAX_MCS[phy] + 1):
                    if phy == "VHT" and not vht_valid(mcs, nss, width):
                        continue
                    for gi in GI[phy]:
                        r = phy_rate(phy, mcs, nss, width, gi)
                        if r is not None and abs(r - rate_mbps) <= tol:
                            found.append({"phy": phy, "mcs": mcs, "nss": nss, "width": width, "gi": gi,
                                          "mod": MOD_NAME[mcs], "rate": round(r, 1)})
    if band != "6" and any(abs(rate_mbps - x) < 0.05 for x in LEGACY_RATES):
        found.append({"phy": "legacy", "mcs": None, "nss": 1, "width": 20, "gi": 0.8, "mod": "", "rate": rate_mbps})

    def score(c):
        return (c["phy"] != max_phy, c["width"] != width_max, c["phy"] == "legacy", c["nss"] != likely_nss,
                c["gi"], c["nss"])
    found.sort(key=score)
    return found[:limit]


def mcs_text(c: Dict[str, Any]) -> str:
    if c["phy"] == "legacy":
        return "legacy %g Мбит/с" % c["rate"]
    return "%s MCS %d (%s), потоков %d, %d МГц, GI %g мкс" % (c["phy"], c["mcs"], c["mod"], c["nss"], c["width"], c["gi"])
