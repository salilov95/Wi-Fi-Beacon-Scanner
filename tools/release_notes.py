"""Текст GitHub Release: ссылки на файлы и разделы CHANGELOG.md (английский) и CHANGELOG.ru.md для версии.

    python tools/release_notes.py 1.0.1 --setup WiFiBeaconScanner-Setup-1.0.1.exe --out release-notes.md
Без --out печатает только разделы CHANGELOG.
"""
import argparse
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# файл и заголовок раздела «ещё не выпущено» (для черновых сборок)
CHANGELOGS = {"en": ("CHANGELOG.md", "Unreleased"), "ru": ("CHANGELOG.ru.md", "Не выпущено")}


def section(version: str, lang: str = "ru") -> str:
    name, unreleased = CHANGELOGS[lang]
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    end = r"(?=^## |^\[[^\]]+\]: |\Z)"
    m = re.search(r"^## \[?%s\]?[^\n]*\n(.*?)%s" % (re.escape(version), end), text, re.S | re.M)
    if not m:      # черновик: раздел Unreleased / «Не выпущено»
        m = re.search(r"^## \[%s\][^\n]*\n(.*?)%s" % (re.escape(unreleased), end), text, re.S | re.M)
    return m.group(1).strip() if m else ""


def notes(version: str, setup: str) -> str:
    en, ru = section(version, "en"), section(version, "ru")
    return ("## Download / Скачать\n\n"
            "- **%s** - installer / установщик (silent / тихая установка: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`)\n"
            "- **WiFiBeaconScanner.exe** - portable, no installation / переносная версия без установки\n"
            "- **SHA256SUMS.txt** - checksums / контрольные суммы\n\n"
            "## What's new\n\n%s\n\n"
            "## Что нового\n\n%s\n" % (setup, en or "See CHANGELOG.md", ru or "см. CHANGELOG.ru.md"))


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
        print(section(a.version, "en"))
        print()
        print(section(a.version, "ru"))
