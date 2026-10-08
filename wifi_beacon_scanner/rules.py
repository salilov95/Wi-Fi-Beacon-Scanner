"""Правила диагностики. Каждое правило - функция (список BSS, настройки) -> список Finding.

Принцип: правило смотрит только на то, что реально видно в эфире. Всё, что требует
знания конфигурации контроллера, формулируется как «проверь», а не как факт.

`focus_ssids` - «наши» SSID. Если задано, проблемы конфигурации и слабого сигнала
считаются только для них, а чужие сети учитываются лишь как помеха на канале.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set

from .model import Bss

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEVERITY_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}


@dataclass
class Thresholds:
    weak_rssi: int = -75          # дБм: ниже - сигнал слабый для работы клиентов
    strong_rssi: int = -70        # дБм: «сильный» сосед для расчёта наложения каналов
    cci_rssi: int = -80           # дБм: соседей слабее этого на канале не считаем
    cci_warn_count: int = 4       # столько BSS на одном канале = предупреждение
    util_warn: float = 50.0       # % занятости канала по QBSS Load
    util_crit: float = 70.0


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    ssid: str = ""
    bssids: List[str] = field(default_factory=list)
    recommendation: str = ""


Rule = Callable[[Sequence[Bss], Thresholds, Set[str]], List[Finding]]


def _is_focus(b: Bss, focus: Set[str]) -> bool:
    return (not focus) or (b.ssid in focus)


def _by_ssid(bss: Sequence[Bss], focus: Set[str]) -> Dict[str, List[Bss]]:
    groups: Dict[str, List[Bss]] = defaultdict(list)
    for b in bss:
        if not b.hidden and _is_focus(b, focus):
            groups[b.ssid].append(b)
    return groups


def _macs(items: Sequence[Bss]) -> List[str]:
    return [b.bssid for b in items]


# ---------------------------------------------------------------- безопасность
def rule_security(bss, th, focus):
    out: List[Finding] = []
    groups: Dict[tuple, List[Bss]] = defaultdict(list)
    for b in bss:
        if _is_focus(b, focus):
            groups[(b.ssid_display, b.security)].append(b)
    for (ssid, sec), items in groups.items():
        base = dict(ssid=ssid, bssids=_macs(items))
        if sec == "Open":
            out.append(Finding(WARNING, "SEC_OPEN", "Открытая сеть без шифрования",
                               "Сеть «%s» не использует шифрование." % ssid,
                               recommendation="Если сеть гостевая - рассмотреть OWE (Enhanced Open) или captive portal; для корпоративной - WPA2/WPA3-Enterprise.",
                               **base))
        elif sec == "WEP":
            out.append(Finding(CRITICAL, "SEC_WEP", "WEP",
                               "Сеть «%s»: установлен бит Privacy, но нет RSN/WPA IE - это WEP." % ssid,
                               recommendation="WEP взламывается за минуты; перевести на WPA2/WPA3.", **base))
        elif sec.startswith("WPA1"):
            out.append(Finding(CRITICAL, "SEC_WPA1_ONLY", "Только WPA1",
                               "Сеть «%s» вещает только WPA1 (vendor IE), RSN отсутствует." % ssid,
                               recommendation="Включить WPA2 (CCMP) минимум.", **base))
        elif sec.endswith("+WPA1"):
            out.append(Finding(WARNING, "SEC_WPA1_MIXED", "Включён режим совместимости с WPA1",
                               "Сеть «%s» объявляет и RSN, и WPA1 IE (%s)." % (ssid, sec),
                               recommendation="Отключить WPA1/TKIP, если нет устройств, которым он нужен.", **base))
        ciphers = set()
        for b in items:
            ciphers.update(b.ciphers)
        if "TKIP" in ciphers and not sec.startswith("WPA1"):
            out.append(Finding(WARNING, "SEC_TKIP", "Разрешён шифр TKIP",
                               "Сеть «%s»: pairwise-шифры %s." % (ssid, ", ".join(sorted(ciphers))),
                               recommendation="TKIP отключает высокие скорости 802.11n+ у многих клиентов и считается устаревшим; оставить только CCMP/GCMP.",
                               **base))
        if "Enterprise" in sec:
            no_pmf = [b for b in items if b.info.rsn and not b.info.rsn.mfp_capable]
            if no_pmf:
                out.append(Finding(INFO, "SEC_NO_PMF", "Защита management-кадров (PMF/802.11w) не включена",
                                   "Сеть «%s»: у %d BSS не выставлен бит MFPC." % (ssid, len(no_pmf)),
                                   recommendation="Включить PMF в режиме optional (или required, если все клиенты поддерживают).",
                                   ssid=ssid, bssids=_macs(no_pmf)))
        if "WPA2/WPA3-Personal" in sec:
            out.append(Finding(INFO, "SEC_TRANSITION", "WPA2/WPA3 transition mode",
                               "Сеть «%s» принимает и PSK, и SAE." % ssid,
                               recommendation="Это нормальный переходный режим; понижение до WPA2 возможно у клиентов, не поддерживающих SAE.",
                               **base))
        wps = [b for b in items if b.info.wps]
        if wps:
            out.append(Finding(INFO, "SEC_WPS", "Включён WPS",
                               "Сеть «%s»: WPS IE присутствует у %d BSS." % (ssid, len(wps)),
                               recommendation="Для корпоративной сети WPS не нужен - выключить.",
                               ssid=ssid, bssids=_macs(wps)))
    return out


# ---------------------------------------------------- согласованность / роуминг
def rule_roaming(bss, th, focus):
    out: List[Finding] = []
    for ssid, items in _by_ssid(bss, focus).items():
        if len(items) < 2:
            continue
        secs = {b.security for b in items}
        if len(secs) > 1:
            out.append(Finding(WARNING, "ROAM_SEC_MISMATCH", "Разная безопасность у BSS одного SSID",
                               "SSID «%s»: %s." % (ssid, "; ".join(sorted(secs))),
                               ssid=ssid, bssids=_macs(items),
                               recommendation="Клиент, выбравший один BSS, может не подключиться к другому. Проверить профиль SSID на контроллере."))
        countries = {b.info.country for b in items if b.info.country}
        if len(countries) > 1:
            out.append(Finding(WARNING, "ROAM_COUNTRY_MISMATCH", "Разные country code у BSS одного SSID",
                               "SSID «%s»: %s." % (ssid, ", ".join(sorted(countries))),
                               ssid=ssid, bssids=_macs(items),
                               recommendation="Country code влияет на набор каналов и мощность; привести к одному значению."))
        for attr, label, code in (("dot11r", "802.11r (FT)", "ROAM_11R"),
                                  ("dot11k", "802.11k", "ROAM_11K"),
                                  ("dot11v", "802.11v", "ROAM_11V")):
            have = [b for b in items if getattr(b.info, attr)]
            miss = [b for b in items if not getattr(b.info, attr)]
            if have and miss:
                out.append(Finding(WARNING, code + "_PARTIAL", "%s включён не на всех BSS" % label,
                                   "SSID «%s»: есть у %d, нет у %d BSS." % (ssid, len(have), len(miss)),
                                   ssid=ssid, bssids=_macs(miss),
                                   recommendation="Проверить, что AP-группы/профили одинаковы."))
            elif not have:
                is_ent = any("Enterprise" in b.security for b in items)
                if attr == "dot11r" and is_ent:
                    out.append(Finding(INFO, code + "_OFF", "802.11r не объявлен",
                                       "SSID «%s» (Enterprise, %d BSS): Mobility Domain IE не найден." % (ssid, len(items)),
                                       ssid=ssid, bssids=_macs(items),
                                       recommendation="Без FT каждый роуминг - это полная 802.1X-аутентификация, если не работают PMK caching/OKC. Включать FT стоит после проверки, что клиенты его поддерживают."))
                elif attr in ("dot11k", "dot11v"):
                    out.append(Finding(INFO, code + "_OFF", "%s не объявлен" % label,
                                       "SSID «%s»: нужный IE не найден ни у одного из %d BSS." % (ssid, len(items)),
                                       ssid=ssid, bssids=_macs(items),
                                       recommendation="Помогает клиентам выбирать лучшую AP при роуминге; включать, если контроллер это поддерживает."))
        beacons = {b.beacon_interval for b in items}
        dtims = {b.info.dtim_period for b in items if b.info.dtim_period is not None}
        if len(beacons) > 1 or len(dtims) > 1:
            out.append(Finding(INFO, "ROAM_TIMERS", "Разные beacon interval / DTIM у BSS одного SSID",
                               "SSID «%s»: beacon=%s, DTIM=%s." % (ssid, sorted(beacons), sorted(dtims)),
                               ssid=ssid, bssids=_macs(items)))
    return out


# --------------------------------------------------------------------- радио
def rule_signal(bss, th, focus):
    out: List[Finding] = []
    for ssid, items in _by_ssid(bss, focus).items():
        best = max(items, key=lambda b: b.rssi)
        if best.rssi < th.weak_rssi:
            out.append(Finding(WARNING, "RF_WEAK", "Слабый сигнал",
                               "SSID «%s»: лучший BSS %d дБм (порог %d)." % (ssid, best.rssi, th.weak_rssi),
                               ssid=ssid, bssids=[best.bssid],
                               recommendation="В этой точке покрытия клиенты будут работать на низких скоростях; проверить расположение AP или мощность."))
    return out


def rule_utilization(bss, th, focus):
    out: List[Finding] = []
    for b in bss:
        u = b.info.qbss_util_pct
        if u is None or not _is_focus(b, focus):
            continue
        if u >= th.util_crit:
            sev = CRITICAL
        elif u >= th.util_warn:
            sev = WARNING
        else:
            continue
        out.append(Finding(sev, "RF_UTIL", "Высокая загрузка канала",
                           "%s (%s, канал %d, %s ГГц): занято %.0f%% эфира, станций: %s."
                           % (b.ssid_display, b.bssid, b.channel, b.band, u, b.info.qbss_stations),
                           ssid=b.ssid_display, bssids=[b.bssid],
                           recommendation="Цифра берётся из QBSS Load самой AP. Проверить число клиентов, смену канала/ширины, перенос клиентов на 5 ГГц."))
    return out


def rule_cochannel(bss, th, focus):
    """Сколько BSS слышно на одном канале (любые SSID, включая чужие)."""
    out: List[Finding] = []
    chans: Dict[tuple, List[Bss]] = defaultdict(list)
    for b in bss:
        if b.rssi >= th.cci_rssi:
            chans[(b.band, b.channel)].append(b)
    for (band, ch), items in sorted(chans.items()):
        if len(items) < th.cci_warn_count:
            continue
        if focus and not any(b.ssid in focus for b in items):
            continue
        out.append(Finding(WARNING, "RF_COCHANNEL", "Много BSS на одном канале",
                           "%s ГГц, канал %d: слышно %d BSS сильнее %d дБм (SSID: %s)."
                           % (band, ch, len(items), th.cci_rssi,
                              ", ".join(sorted({b.ssid_display for b in items})[:6])),
                           bssids=_macs(items),
                           recommendation="Все они делят эфир (CSMA/CA). Рассмотреть другой канал, меньшую ширину или меньшую мощность."))
    return out


def rule_24ghz(bss, th, focus):
    out: List[Finding] = []
    nonstd = [b for b in bss if b.band == "2.4" and b.channel not in (1, 6, 11) and _is_focus(b, focus)]
    if nonstd:
        out.append(Finding(WARNING, "RF_24_NONSTD", "2.4 ГГц: канал не 1/6/11",
                           "Каналы: %s." % ", ".join(str(c) for c in sorted({b.channel for b in nonstd})),
                           bssids=_macs(nonstd),
                           recommendation="Каналы 2.4 ГГц перекрываются; вне 1/6/11 AP мешает сразу двум соседним."))
    wide = [b for b in bss if b.band == "2.4" and b.info.width_mhz >= 40 and _is_focus(b, focus)]
    if wide:
        out.append(Finding(WARNING, "RF_24_40MHZ", "2.4 ГГц: ширина канала 40 МГц",
                           "BSS с 40 МГц: %d." % len(wide), bssids=_macs(wide),
                           recommendation="В 2.4 ГГц 40 МГц занимает почти полдиапазона; оставить 20 МГц."))
    strong = [b for b in bss if b.band == "2.4" and b.rssi >= th.strong_rssi]
    pairs = set()
    for i, a in enumerate(strong):
        for c in strong[i + 1:]:
            d = abs(a.channel - c.channel)
            if 1 <= d <= 4:
                pairs.add(tuple(sorted((a.channel, c.channel))))
    if pairs:
        out.append(Finding(WARNING, "RF_24_OVERLAP", "2.4 ГГц: сильные BSS на перекрывающихся каналах",
                           "Пары каналов: %s." % ", ".join("%d/%d" % p for p in sorted(pairs)),
                           bssids=_macs(strong),
                           recommendation="Перекрытие хуже, чем совпадение каналов: устройства не могут договориться через CSMA/CA и воспринимают друг друга как шум."))
    return out


def rule_dfs(bss, th, focus):
    dfs = [b for b in bss if b.band == "5" and 52 <= b.channel <= 144 and _is_focus(b, focus)]
    if not dfs:
        return []
    return [Finding(INFO, "RF_DFS", "5 ГГц: используются DFS-каналы",
                    "Каналы: %s." % ", ".join(str(c) for c in sorted({b.channel for b in dfs})),
                    bssids=_macs(dfs),
                    recommendation="При обнаружении радара AP обязана уйти с канала; если есть жалобы на кратковременные пропадания - сверить с логами радара на контроллере.")]


# ------------------------------------------------------------------- гигиена
def rule_hygiene(bss, th, focus):
    out: List[Finding] = []
    legacy_basic = []
    for b in bss:
        if b.band == "2.4" and _is_focus(b, focus):
            if any(basic and mbps in (1.0, 2.0, 5.5, 11.0) for mbps, basic in b.info.rates):
                legacy_basic.append(b)
    if legacy_basic:
        out.append(Finding(INFO, "HYG_BASIC_RATES", "2.4 ГГц: 802.11b-скорости в basic rate set",
                           "BSS: %d." % len(legacy_basic), bssids=_macs(legacy_basic),
                           recommendation="Пока 1/2/5.5/11 Мбит/с обязательны, служебные кадры уходят на низкой скорости и занимают эфир. Отключить, если b-клиентов нет."))
    prot = [b for b in bss if b.info.ht_protection and _is_focus(b, focus)]
    if prot:
        out.append(Finding(INFO, "HYG_HT_PROT", "HT protection включён",
                           "BSS: %d (mode %s)." % (len(prot), sorted({b.info.ht_protection for b in prot})),
                           bssids=_macs(prot),
                           recommendation="AP видит legacy-клиентов или соседние non-HT сети; это снижает пропускную способность."))
    legacy = [b for b in bss if b.info.generation == 0 and _is_focus(b, focus)]
    if legacy:
        out.append(Finding(WARNING, "HYG_LEGACY_PHY", "BSS без HT (только 802.11a/b/g)",
                           "BSS: %d." % len(legacy), bssids=_macs(legacy),
                           recommendation="Максимум 54 Мбит/с; проверить, что это не отключённый радиомодуль или старая AP."))
    for ssid, items in _by_ssid(bss, focus).items():
        bands = {b.band for b in items}
        if bands == {"2.4"} and len(items) >= 1:
            out.append(Finding(INFO, "HYG_24_ONLY", "SSID слышен только в 2.4 ГГц",
                               "SSID «%s»." % ssid, ssid=ssid, bssids=_macs(items),
                               recommendation="Если сеть должна быть и в 5 ГГц - проверить радио 5 ГГц и привязку SSID."))
    hidden = [b for b in bss if b.hidden and _is_focus(b, focus)]
    if hidden:
        out.append(Finding(INFO, "HYG_HIDDEN", "Скрытые SSID",
                           "BSS со скрытым SSID: %d." % len(hidden), bssids=_macs(hidden),
                           recommendation="Скрытие SSID не защита; клиенты при этом шлют probe с именем сети."))
    return out


ALL_RULES: List[Rule] = [
    rule_security, rule_roaming, rule_signal, rule_utilization,
    rule_cochannel, rule_24ghz, rule_dfs, rule_hygiene,
]


def analyze(bss: Sequence[Bss], th: Optional[Thresholds] = None,
            focus_ssids: Optional[Sequence[str]] = None) -> List[Finding]:
    th = th or Thresholds()
    focus = set(focus_ssids or [])
    findings: List[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(bss, th, focus))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.code, f.ssid))
    return findings


def channel_advice(bss: Sequence[Bss], band: str, busy_util: float = 50.0) -> List[dict]:
    """Оценка свободности каналов: суммарная мощность соседей, чья полоса накрывает канал (дБм).

    Полоса BSS берётся из её центра и ширины (в номерах каналов: 20 МГц = ±2 канала), поэтому точка
    80 МГц на канале 36 считается помехой для 36, 40, 44 и 48. В 2.4 ГГц добавлен запас на «хвосты»
    спектральной маски: каналы 1 и 5 считаются перекрывающимися, 1 и 6 - нет.
    Чем ниже дБм, тем свободнее канал; каналы с загрузкой QBSS >= busy_util идут в конец списка.
    Считаются только BSS, которые слышит адаптер в этой точке.
    """
    if band == "2.4":
        cands, margin = [1, 6, 11], 2.5
    elif band == "5":
        cands, margin = [36, 40, 44, 48, 149, 153, 157, 161], 2.0
    else:
        return []

    def near(b: Bss, c: int) -> bool:
        return abs(b.center_channel - c) < b.info.width_mhz / 10.0 + margin

    rows = []
    for c in cands:
        es = [b for b in bss if b.band == band and b.rssi >= -95 and near(b, c)]
        energy = sum(10 ** (b.rssi / 10.0) for b in es)
        dbm = round(10 * math.log10(energy), 1) if energy > 0 else -120.0
        util = max([b.info.qbss_util_pct or 0.0 for b in es] or [0.0])
        rows.append({"channel": c, "dbm": dbm, "count": len(es), "util": round(util, 1),
                     "dfs": band == "5" and 52 <= c <= 144})
    # Сначала отсекаем каналы, где какая-то AP сама сообщает о высокой загрузке эфира:
    # тихий по уровню сигнала, но занятый на 80% канал свободным не является.
    for r in rows:
        r["busy"] = r["util"] >= busy_util
    rows.sort(key=lambda r: (r["busy"], r["dbm"], r["count"]))
    for i, r in enumerate(rows):
        r["best"] = i == 0
    return rows


UTIL_LEVELS = [(70.0, "crit", "перегружен"), (50.0, "high", "высокая"), (30.0, "mid", "умеренная"), (0.0, "low", "свободен")]


def util_level(u: float):
    for lo, key, label in UTIL_LEVELS:
        if u >= lo:
            return key, label
    return "low", "свободен"


def channel_utilization(bss: Sequence[Bss], history: Optional[dict] = None) -> dict:
    """Загрузка каналов по QBSS Load (IE 11): доля времени, когда сама AP видит эфир занятым.

    Возвращает {"channels": [...], "no_data": [...]}. На канал берётся максимум по AP, которые
    сообщают загрузку: эфир один на всех, и самая занятая AP точнее всего показывает худший случай.
    Каналы, где ни одна AP не вещает QBSS Load, попадают в no_data: там загрузка неизвестна, а не нулевая.
    history: {bssid: [(t, rssi, util), ...]} - для мини-графика максимума загрузки по времени.
    """
    groups: Dict[tuple, List[Bss]] = defaultdict(list)
    for b in bss:
        groups[(b.band, b.channel)].append(b)
    channels, no_data = [], []
    for (band, ch), items in groups.items():
        rep = [b for b in items if b.info.qbss_util_pct is not None]
        if not rep:
            no_data.append({"band": band, "channel": ch, "bss": len(items)})
            continue
        vals = [b.info.qbss_util_pct for b in rep]
        mx = max(vals)
        key, label = util_level(mx)
        series: List[list] = []
        if history:
            per_t: Dict[float, float] = {}
            for b in rep:
                for p in history.get(b.bssid, []):
                    if len(p) > 2 and p[2] is not None:
                        per_t[p[0]] = max(per_t.get(p[0], 0.0), p[2])
            series = [[t, per_t[t]] for t in sorted(per_t)][-60:]
        channels.append({
            "band": band, "channel": ch, "max": mx, "avg": round(sum(vals) / len(vals), 1),
            "level": key, "label": label, "reporting": len(rep), "bss": len(items),
            "stations": sum(b.info.qbss_stations or 0 for b in rep),
            "aps": sorted(({"bssid": b.bssid, "ssid": b.ssid_display, "util": b.info.qbss_util_pct,
                            "stations": b.info.qbss_stations} for b in rep), key=lambda a: -a["util"]),
            "series": series,
        })
    channels.sort(key=lambda c: (-c["max"], c["band"], c["channel"]))
    no_data.sort(key=lambda c: (c["band"], c["channel"]))
    return {"channels": channels, "no_data": no_data}
