"""Демо-данные: синтетический «офис с соседями». Нужны, чтобы посмотреть интерфейс без
сканирования и чтобы тестировать GUI на машине без Wi-Fi. MAC-адреса вымышленные."""
from __future__ import annotations

from typing import List

from .model import Bss, Snapshot, now_iso
from .synth import (
    country_ie, ext_caps_ie, he_cap_ie, he_op_ie, ht_cap_ie, ht_op_ie, make_bss, mobility_domain_ie, qbss_ie, rates_ie,
    rm_caps_ie, rsn_ie, tim_ie, vendor_ie, vht_cap_ie, vht_op_ie, wpa1_ie,
)

F24 = {1: 2_412_000, 6: 2_437_000, 11: 2_462_000, 3: 2_422_000, 9: 2_452_000}


def _f5(ch: int) -> int:
    return 5_000_000 + ch * 5000


def _f6(ch: int) -> int:
    return 5_950_000 + ch * 5000


def build_demo_snapshot() -> Snapshot:
    bss: List[Bss] = []
    ru = country_ie("RU")

    def corp(mac, ch24, rssi24, ch5, rssi5, c5, ft=True, util=None, tkip=False, k=True, v=True):
        pair = [4, 2] if tkip else [4]
        akm = [1, 3] if ft else [1]
        common = rsn_ie(akm, pairwise=pair, mfpc=True) + ru + tim_ie(1)
        if ft:
            common += mobility_domain_ie(0x4F52)
        if k:
            common += rm_caps_ie()
        if v:
            common += ext_caps_ie()
        extra = qbss_ie(util[0], util[1]) if util else b""
        bss.append(make_bss("00:e0:fc:10:%02x:01" % mac, "CORP", F24[ch24], rssi24,
                            common + extra + rates_ie([6, 9, 12, 18, 24, 36, 48, 54], basic=[6, 12, 24])
                            + ht_cap_ie(2) + ht_op_ie(ch24)))
        bss.append(make_bss("00:e0:fc:10:%02x:02" % mac, "CORP", _f5(ch5), rssi5,
                            common + extra + ht_cap_ie(2) + ht_op_ie(ch5, True, 1) + vht_cap_ie(2)
                            + vht_op_ie(1, c5) + he_cap_ie() + he_op_ie(color=mac)))

    corp(0x01, 1, -48, 36, -45, 42, util=(14, 60))
    corp(0x02, 6, -55, 52, -52, 58, util=(9, 40))
    corp(0x03, 11, -61, 100, -58, 106, util=(31, 205))     # загруженная точка
    corp(0x04, 1, -72, 149, -66, 155, ft=False, k=False, v=False)  # точка с «забытым» профилем
    corp(0x05, 6, -77, 44, -70, 42, tkip=True, util=(5, 25))
    corp(0x06, 11, -83, 132, -80, 138)

    # 6 ГГц: HT/VHT Operation тут нет, ширина и центр канала берутся из HE Operation (6 GHz Operation Information)
    six = rsn_ie([1, 3], mfpc=True, mfpr=True) + ru + tim_ie(1) + mobility_domain_ie(0x4F52) + rm_caps_ie() + ext_caps_ie()
    bss.append(make_bss("00:e0:fc:10:01:03", "CORP", _f6(37), -57,
                        six + qbss_ie(6, 30) + he_cap_ie(2, 2, w160=True) + he_op_ie(1, six=(37, 2, 39, 0))))
    bss.append(make_bss("00:e0:fc:10:02:03", "CORP", _f6(69), -64,
                        six + qbss_ie(3, 18) + he_cap_ie(2, 2, w160=True) + he_op_ie(2, six=(69, 3, 71, 79))))

    guest = rsn_ie([8], mfpc=True, mfpr=True)
    bss.append(make_bss("00:e0:fc:20:01:01", "CORP-Guest", F24[1], -49, b"" + ru + ht_cap_ie() + ht_op_ie(1),
                        capability=0x0401))
    bss.append(make_bss("00:e0:fc:20:02:01", "CORP-Guest", F24[6], -57, guest + ru + ht_cap_ie() + ht_op_ie(6)))
    bss.append(make_bss("00:e0:fc:30:01:01", "IoT-Sensors", F24[11], -64,
                        rsn_ie([2], pairwise=[2, 4]) + wpa1_ie() + rates_ie([1, 2, 5.5, 11, 6], basic=[1, 2, 5.5, 11])
                        + ht_cap_ie(1) + ht_op_ie(11, protection=3)
                        + vendor_ie(b"\x00\x11\x22", 1, b"demo-ap-name\x00")))

    # соседи
    bss.append(make_bss("3c:37:86:aa:00:01", "Neighbor-2G", F24[6], -66, rsn_ie([2]) + ht_cap_ie() + ht_op_ie(6)))
    bss.append(make_bss("3c:37:86:aa:00:02", "Neighbor-5G", _f5(36), -71,
                        rsn_ie([2, 8], mfpc=True) + ht_cap_ie() + ht_op_ie(36, True, 1) + vht_cap_ie(2)
                        + vht_op_ie(1, 42) + he_cap_ie()))
    bss.append(make_bss("00:00:0c:bb:00:01", "Hotel-WiFi", F24[3], -68, b"" + ht_cap_ie() + ht_op_ie(3, True, 1)
                        + rates_ie([1, 2, 5.5, 11], basic=[1, 2]), capability=0x0401))
    bss.append(make_bss("00:00:0c:bb:00:02", "Hotel-WiFi", F24[9], -74, b"" + ht_cap_ie() + ht_op_ie(9),
                        capability=0x0401))
    bss.append(make_bss("02:cc:00:00:00:01", "", F24[11], -79, rsn_ie([2]) + ht_cap_ie() + ht_op_ie(11)))
    bss.append(make_bss("02:cc:00:00:00:02", "Printer-Direct", F24[1], -62, wpa1_ie(akm=2, cipher=2)
                        + rates_ie([1, 2, 5.5, 11], basic=[1, 2])))
    return Snapshot(taken_at=now_iso(), interface="Demo adapter", bss=bss)
