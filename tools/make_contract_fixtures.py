"""Синтетические снапшоты контракта, которые покрывают ветки разбора IE и правил.

    python tools/make_contract_fixtures.py     - перезаписать contract/fixtures/synthetic-coverage.json

Зачем: эталоны из реального скана и демо не проходят по многим веткам (поле Tx MCS Set = 3,
TPC с отрицательной мощностью, 6 ГГц с флагами HE Operation, ничьи по RSSI внутри SSID и т. п.).
Без них версия на Rust могла бы ошибиться там, и сверка с эталоном этого не заметила бы.
Каждый BSS ниже подписан: какую ветку он проверяет. Байты собраны по стандарту (synth.py), а не
парсером программы. После изменения - `python tools/golden.py update`.
"""
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi_beacon_scanner.model import Snapshot  # noqa: E402
from wifi_beacon_scanner.synth import (  # noqa: E402
    CH1, CH6, CH36, anqp_ie, ext_caps_ie, he_cap_ie, he_op_ie, hs20_ie, ht_op_ie, ie, interworking_ie,
    make_bss, mcs_map, mobility_domain_ie, power_constraint_ie, rates_ie, rm_caps_ie, rsn_ie, tim_ie,
    tpc_report_ie, vendor_ie, wmm_ie, wpa1_ie,
)

PATH = os.path.join(ROOT, "contract", "fixtures", "synthetic-coverage.json")


def ht_cap(streams: int, tx: int, highest: int = 0, short: bool = False) -> bytes:
    """HT Capabilities: tx - байт Tx MCS Set Parameters (0, 1 или 3), highest - Rx Highest Data Rate."""
    if short:                                    # обрезанный HT Cap: только flags + A-MPDU + 4 байта маски
        return ie(45, struct.pack("<HB", 0x006E, 0x17) + bytes([0xFF] * streams + [0] * (4 - streams)))
    mcs = bytes([0xFF] * streams + [0] * (10 - streams)) + struct.pack("<H", highest) + bytes([tx, 0, 0, 0])
    return ie(45, struct.pack("<HB", 0x01EF, 0x17) + mcs + b"\x00" * 7)


def vht_cap(rx: int, tx: int, caps: int) -> bytes:
    return ie(191, struct.pack("<IHHHH", caps, rx, 0, tx, 0))


def build():
    b = []
    # 1-2: одинаковый SSID, одинаковый RSSI (ничья: max() в Python берёт первый), Tx MCS Set 1 и 3, слабый сигнал
    b.append(make_bss("02:10:00:00:01:00", "Cov-Tie", CH36, -80, rsn_ie([2]) + ht_cap(2, 0x01, highest=300)
                      + ht_op_ie(36, True, 1, protection=1, basic_mcs=0xFF) + tim_ie(3)))
    b.append(make_bss("02:10:00:00:02:00", "Cov-Tie", CH36, -80, rsn_ie([2]) + ht_cap(2, 0x03)
                      + ht_op_ie(36, True, 3, protection=2) + tim_ie(1), beacon=102))
    # 3: обрезанный HT Cap (меньше 19 байт), Tx MCS Set 0, 2.4 ГГц с b-скоростями в basic
    b.append(make_bss("02:10:00:00:03:00", "Cov-Short", CH1, -60, rsn_ie([2], pairwise=[4, 2]) + ht_cap(1, 0, short=True)
                      + ht_op_ie(1) + rates_ie([1, 2, 5.5, 11, 6, 54], basic=[1, 2, 5.5, 11])))
    # 4: 802.11h и 802.11e: Power Constraint, TPC с отрицательной мощностью и link margin, CSA, EDCA, биты Capability
    b.append(make_bss("02:10:00:00:04:00", "Cov-11h", CH36, -55, rsn_ie([1, 3], mfpc=False) + power_constraint_ie(6)
                      + tpc_report_ie(-3, 12) + ie(37, bytes([1, 52, 5])) + ie(12, bytes(18)) + wmm_ie()
                      + ht_cap(2, 0x01) + ht_op_ie(36), capability=0x0311))
    # 5: 802.11u / Passpoint и Extended Capabilities с многими битами
    b.append(make_bss("02:10:00:00:05:00", "Cov-11u", CH6, -50, rsn_ie([1], mfpc=True) + interworking_ie(2, True) + anqp_ie()
                      + ie(111, bytes([0, 1, 2, 3])) + hs20_ie()
                      + ext_caps_ie(True, bits=[2, 12, 17, 22, 31, 46, 70, 71, 72, 77, 78]) + ht_cap(1, 0) + ht_op_ie(6)))
    # 6: Interworking без интернета, тип без имени (9); Mesh ID; RM без neighbor report; Mobility Domain без FT over DS
    b.append(make_bss("02:10:00:00:06:00", "Cov-Mesh", CH6, -58, rsn_ie([8], mfpc=True, mfpr=True) + interworking_ie(9, False)
                      + ie(114, b"mesh-1") + rm_caps_ie(False) + mobility_domain_ie(0xBEEF, False) + ht_cap(1, 0) + ht_op_ie(6)))
    # 7: пустой Mesh ID и пустой SSID IE у видимой сети (имя из WLAN_BSS_ENTRY)
    b.append(make_bss("02:10:00:00:07:00", "Cov-EmptyIE", CH6, -59, ie(0, b"") + ie(114, b"") + rsn_ie([2])))
    # 8: VHT Cap с разными картами по потокам, Tx-картой, 160 и beamformer; VHT Op ширина 0
    b.append(make_bss("02:10:00:00:08:00", "Cov-VHT", CH36, -52, rsn_ie([2]) + ht_cap(3, 0x01) + ht_op_ie(36, True, 1)
                      + vht_cap(0xFFE4, mcs_map(2, 1), caps=(1 << 2) | 0x60 | (1 << 11) | (1 << 19))
                      + ie(192, bytes([0, 0, 0, 0xFC, 0xFF]))))
    # 9: VHT Cap: потоков нет (вся карта 3), ширины 2 (160 и 80+80); VHT Op неизвестной ширины 7
    b.append(make_bss("02:10:00:00:09:00", "Cov-VHT", CH36, -66, rsn_ie([2]) + ht_cap(1, 0) + ht_op_ie(36)
                      + vht_cap(0xFFFF, 0xFFFF, caps=(2 << 2)) + ie(192, bytes([7, 0, 0]))))
    # 10: HE в 6 ГГц: карты для 160, флаги VHT info и co-hosted BSSID, 6 GHz Operation, BSS Color отключён
    he_op_body = bytes([36]) + ((1 << 17) | (1 << 14) | (1 << 15) | 0x08 | (1 << 16)).to_bytes(3, "little") \
        + bytes([0x80 | 7]) + struct.pack("<H", 0xFFFC) + bytes([1, 42, 0]) + bytes([3]) + bytes([37, 3, 39, 47, 12])
    b.append(make_bss("02:10:00:00:0a:00", "Cov-6G", 6_135_000, -62, rsn_ie([8, 24], mfpc=True, mfpr=True)
                      + he_cap_ie(2, 2, w160=True, twt=True) + ie(255, he_op_body)))
    # 11: HE в 6 ГГц 20 МГц (короткая HE Operation без 6 ГГц-части) и EHT-расширения, неизвестное расширение, пустое 255
    b.append(make_bss("02:10:00:00:0b:00", "Cov-EHT", 5_955_000, -64, rsn_ie([24], mfpc=True, mfpr=True)
                      + he_cap_ie(1, 0) + he_op_ie(color=9, six=(1, 0, 1, 0)) + ie(255, bytes([106, 0, 0]))
                      + ie(255, bytes([108, 1])) + ie(255, bytes([38, 1, 2])) + ie(255, b"")))
    # 12: vendor IE: Microsoft тип 5, WPA1-Enterprise, чужой OUI с текстом; RSN слишком короткий; пустой DS; короткий TIM;
    #     неизвестный элемент 200; Multiple BSSID; Country с не-ASCII байтом
    b.append(make_bss("02:10:00:00:0c:00", "Cov-Vendor", CH6, -70, ie(48, b"\x01") + wpa1_ie(akm=1, cipher=4)
                      + vendor_ie(b"\x00\x50\xf2", 5, b"\x01\x02") + vendor_ie(b"\x00\x0c\xe7", 8, b"Hello-AP\x00\x01")
                      + ie(3, b"") + ie(5, b"\x00") + ie(200, bytes(range(70))) + ie(71, b"\x03\x00\x00")
                      + ie(7, b"R\xd0 \x01\x0d\x14")))
    # 13: скрытый SSID из нулей, WEP (бит Privacy без RSN), открытая сеть, только селекторы в Extended Rates
    b.append(make_bss("02:10:00:00:0d:00", "\x00\x00\x00", CH1, -71, rates_ie([1, 2]) + ht_cap(1, 0) + ht_op_ie(1)))
    b.append(make_bss("02:10:00:00:0e:00", "Cov-WEP", CH1, -72, rates_ie([1, 2, 5.5, 11]), capability=0x0411))
    b.append(make_bss("02:10:00:00:0f:00", "Cov-Open", CH1, -73, rates_ie([6, 12]) + ie(50, bytes([0xFF, 0xFE])),
                      capability=0x0401))
    # 16-18: SSID на трёх BSS: разные страны, beacon и DTIM, 11r/11k/11v частично, Enterprise без 11r, разная защита
    common = ht_cap(2, 0x01) + ht_op_ie(36)
    b.append(make_bss("02:10:00:00:10:00", "Cov-Roam", CH36, -48, rsn_ie([1], mfpc=False) + ie(7, b"RU ") + tim_ie(1)
                      + rm_caps_ie(True) + ext_caps_ie(True) + common, beacon=100))
    b.append(make_bss("02:10:00:00:11:00", "Cov-Roam", CH36, -49, rsn_ie([1], mfpc=False) + ie(7, b"US ") + tim_ie(2)
                      + common, beacon=200))
    b.append(make_bss("02:10:00:00:12:00", "Cov-Roam", 5_745_000, -50, rsn_ie([1, 3], mfpc=True, mfpr=True)
                      + mobility_domain_ie(1, True) + common, beacon=100))
    # 19-20: два разных радио с одинаковой загрузкой (ничья в max()), ещё одно радио на канале
    q = ie(11, struct.pack("<HBH", 7, 230, 10))
    b.append(make_bss("02:10:00:00:13:00", "Cov-Util", CH36, -61, rsn_ie([2]) + q + common))
    b.append(make_bss("02:10:00:00:14:00", "Cov-Util", CH36, -61, rsn_ie([2]) + q + common))
    b.append(make_bss("02:10:00:00:14:01", "Cov-Util-2", CH36, -61, rsn_ie([2]) + ie(11, struct.pack("<HBH", 3, 230, 0)) + common))
    return Snapshot("2026-10-15T00:00:00+03:00", "synthetic", b)


def main() -> int:
    data = json.loads(build().to_json())
    with open(PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("записан %s: BSS %d" % (os.path.relpath(PATH, ROOT), len(data["bss"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
