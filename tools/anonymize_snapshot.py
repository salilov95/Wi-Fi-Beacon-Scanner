"""Обезличивание снапшота перед тем, как положить его в публичный репозиторий.

    python tools/anonymize_snapshot.py снапшот.json обезличенный.json [--map карта.json]

Что заменяется:
  * SSID - на net-01, net-02, ... (в поле ssid_hex, в SSID IE, в Mesh ID и в профилях Multiple BSSID);
    скрытые SSID (пустые или из нулей) остаются как есть;
  * BSSID - OUI (первые 3 октета) и младшие 4 бита последнего октета сохраняются, остальное заменяется
    детерминированно: вендор по OUI и группировка BSSID в радио (rules.radio_key) не меняются;
    у адресов с битом locally administered (случайных) заменяется всё, кроме первого октета;
  * WPS IE: всё, кроме служебных атрибутов (версия, состояние, методы, тип устройства), затирается -
    там имя устройства, производитель, модель, серийный номер, UUID;
  * остальные vendor IE (кроме WPA1 и WMM): текстовые фрагменты от 4 символов затираются буквой x;
  * в конце любые 6-байтовые совпадения с исходными BSSID внутри IE заменяются на новые.

Что остаётся: каналы, частоты, RSSI, beacon interval, capability, все остальные IE (RSN, HT/VHT/HE, QBSS,
country...), время снапшота и имя адаптера. Проверка в конце: исходных SSID и BSSID в результате нет.
Карта замен (--map) нужна только для себя - в репозиторий её не класть.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Dict, List, Tuple

OUI_MS = bytes.fromhex("0050f2")
# атрибуты WPS, которые ничего не говорят об устройстве (Wi-Fi Simple Configuration, таблица атрибутов).
# Vendor Extension (0x1049) сюда не входит: в нём встречается копия UUID устройства.
WPS_KEEP = {0x104A, 0x1044, 0x1057, 0x1041, 0x1012, 0x1053, 0x103B, 0x1054, 0x103C, 0x1008}
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")


def _iter(data: bytes):
    pos = 0
    while pos + 2 <= len(data):
        eid, ln = data[pos], data[pos + 1]
        body = data[pos + 2: pos + 2 + ln]
        if len(body) < ln:
            break
        yield eid, body
        pos += 2 + ln
    tail = data[pos:]
    if tail:
        yield None, tail          # обрезанный хвост сохраняем как есть


def _ie(eid: int, body: bytes) -> bytes:
    if len(body) > 255:
        raise ValueError("IE %d длиннее 255 байт после замены" % eid)
    return bytes([eid, len(body)]) + body


def _hidden(ssid: bytes) -> bool:
    return len(ssid) == 0 or all(x == 0 for x in ssid)


class Anonymizer:
    def __init__(self) -> None:
        self.ssids: Dict[bytes, bytes] = {}
        self.radios: Dict[str, str] = {}      # первые 16 символов MAC (без младшего полубайта) -> новые
        self.macs: Dict[str, str] = {}
        self.vendor_texts: set = set()         # текстовые фрагменты исходных vendor IE - для проверки утечек

    def ssid(self, s: bytes) -> bytes:
        if _hidden(s):
            return s
        if s not in self.ssids:
            self.ssids[s] = ("net-%02d" % (len(self.ssids) + 1)).encode()
        return self.ssids[s]

    def mac(self, m: str) -> str:
        m = m.lower()
        if m not in self.macs:
            head = m[:16]                      # "aa:bb:cc:dd:ee:f" - всё, кроме младшего полубайта
            if head not in self.radios:
                n = len(self.radios) + 1
                first = int(m[:2], 16)
                if first & 0x02:              # случайный адрес: первый октет оставляем (биты LA/групповой)
                    self.radios[head] = "%02x:%02x:%02x:%02x:%02x:%x" % (
                        first, 0xA0, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF, 0)
                else:                         # OUI вендора оставляем
                    self.radios[head] = "%s:%02x:%02x:%x" % (m[:8], 0xA0 | (n >> 12 & 0x0F), (n >> 4) & 0xFF, n & 0x0F)
            self.macs[m] = self.radios[head] + m[16]
        return self.macs[m]

    # ---------------------------------------------------------------- IE
    def _wps(self, body: bytes) -> bytes:
        out, pos = bytearray(body[:4]), 4       # OUI + тип
        while pos + 4 <= len(body):
            t = int.from_bytes(body[pos:pos + 2], "big")
            ln = int.from_bytes(body[pos + 2:pos + 4], "big")
            val = body[pos + 4: pos + 4 + ln]
            if t not in WPS_KEEP:
                val = bytes(0x78 if 0x20 <= x < 0x7F else 0 for x in val)
            out += body[pos:pos + 4] + val
            pos += 4 + ln
        out += body[pos:]
        return bytes(out)

    def _vendor(self, body: bytes) -> bytes:
        self.vendor_texts.update(m.group() for m in PRINTABLE_RUN.finditer(body[4:]) if m.group().strip(b"x0 "))
        if len(body) >= 4 and body[:3] == OUI_MS and body[3] in (1, 2):
            return body                         # WPA1 и WMM - только двоичные поля
        if len(body) >= 4 and body[:3] == OUI_MS and body[3] == 4:
            return self._wps(body)
        return body[:4] + PRINTABLE_RUN.sub(lambda m: b"x" * len(m.group()), body[4:])

    def _mbssid(self, body: bytes) -> bytes:
        """Multiple BSSID (71): в профилях nontransmitted BSSID есть свои SSID IE."""
        if not body:
            return body
        out, pos = bytearray(body[:1]), 1
        while pos + 2 <= len(body):
            sid, ln = body[pos], body[pos + 1]
            sub = body[pos + 2: pos + 2 + ln]
            if sid == 0:
                sub = self.ies(sub)
            out += bytes([sid, len(sub)]) + sub
            pos += 2 + ln
        out += body[pos:]
        return bytes(out)

    def ies(self, data: bytes) -> bytes:
        out = bytearray()
        for eid, body in _iter(data):
            if eid is None:
                out += body
            elif eid == 0:
                out += _ie(0, self.ssid(body))
            elif eid == 114 and body:
                out += _ie(114, ("mesh-%02d" % (len(self.ssids) + 1)).encode())
            elif eid == 221:
                out += _ie(221, self._vendor(body))
            elif eid == 71:
                out += _ie(71, self._mbssid(body))
            else:
                out += _ie(eid, body)
        return bytes(out)

    # ---------------------------------------------------------------- снапшот
    def snapshot(self, d: dict) -> dict:
        for x in d["bss"]:                      # сначала все BSSID, чтобы порядок номеров не зависел от IE
            self.mac(x["bssid"])
        res = dict(d)
        res["bss"] = []
        for x in d["bss"]:
            y = dict(x)
            y["bssid"] = self.mac(x["bssid"])
            y["ssid_hex"] = self.ssid(bytes.fromhex(x["ssid_hex"])).hex()
            ie = self.ies(bytes.fromhex(x["ie_hex"]))
            for old, new in self.macs.items():  # BSSID внутри IE (RNR, Neighbor Report, ...)
                ie = ie.replace(bytes.fromhex(old.replace(":", "")), bytes.fromhex(new.replace(":", "")))
            y["ie_hex"] = ie.hex()
            res["bss"].append(y)
        return res

    def leaks(self, d: dict) -> List[str]:
        """Что из исходного осталось в результате: SSID от 3 символов и BSSID - в любом виде."""
        text = json.dumps(d).lower()
        blob = b"".join(bytes.fromhex(x["ie_hex"]) + bytes.fromhex(x["ssid_hex"]) for x in d["bss"])
        found = []
        for s in self.ssids:
            if len(s) >= 3 and (s in blob or s.hex() in text):
                found.append("SSID %r" % s)
        for t in self.vendor_texts:
            if t in blob:
                found.append("текст vendor IE %r" % t)
        for m in self.macs:
            if m in text or bytes.fromhex(m.replace(":", "")) in blob or m.replace(":", "") in text:
                found.append("BSSID %s" % m)
        return found


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("--map", help="куда сохранить карту замен (только для себя)")
    a = p.parse_args(argv)
    with open(a.src, encoding="utf-8") as f:
        src = json.load(f)
    an = Anonymizer()
    dst = an.snapshot(src)
    bad = an.leaks(dst)
    if bad:
        print("ОШИБКА: в результате остались исходные данные: %s" % ", ".join(bad), file=sys.stderr)
        return 1
    with open(a.dst, "w", encoding="utf-8") as f:
        json.dump(dst, f, ensure_ascii=False, indent=1)
        f.write("\n")
    if a.map:
        with open(a.map, "w", encoding="utf-8") as f:
            json.dump({"ssid": {k.decode("utf-8", "replace"): v.decode() for k, v in an.ssids.items()},
                       "bssid": an.macs}, f, ensure_ascii=False, indent=1)
    print("BSS: %d, SSID заменено: %d, BSSID: %d (радио: %d)" % (len(dst["bss"]), len(an.ssids), len(an.macs), len(an.radios)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
