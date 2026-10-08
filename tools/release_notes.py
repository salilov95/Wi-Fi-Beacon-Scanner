"""Текст GitHub Release: ссылки на файлы и раздел CHANGELOG.md для версии.

    python tools/release_notes.py 0.7.0 --setup WiFiBeaconScanner-Setup-0.7.0.exe --out release-notes.md
Без --out печатает только раздел CHANGELOG.
"""
import argparse
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def section(version: str) -> str:
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^## \[?%s\]?[^\n]*\n(.*?)(?=^## |^\[[^\]]+\]: |\Z)" % re.escape(version), text, re.S | re.M)
    return m.group(1).strip() if m else ""


def notes(version: str, setup: str) -> str:
    return ("## Скачать\n\n"
            "- **%s** - установщик (тихая установка: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`)\n"
            "- **WiFiBeaconScanner.exe** - переносная версия без установки\n"
            "- **SHA256SUMS.txt** - контрольные суммы\n\n"
            "## Что нового\n\n%s\n" % (setup, section(version) or "см. CHANGELOG.md"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--setup", default="WiFiBeaconScanner-Setup.exe")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(notes(a.version, a.setup))
    else:
        print(section(a.version))
