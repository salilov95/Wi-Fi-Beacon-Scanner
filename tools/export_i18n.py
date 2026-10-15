"""Выгрузка каталога переводов в contract/i18n/en.json - общий ресурс для Python 1.x и версии на Rust.

    python tools/export_i18n.py          - перезаписать contract/i18n/en.json из wifi_beacon_scanner/i18n_en.py
    python tools/export_i18n.py check    - проверить, что файл совпадает с каталогом (это же делает тест)

Источник правды пока - i18n_en.py (ключ - русская строка, значение - английская). Файл JSON пишется с
сортировкой ключей, чтобы изменения в переводах были видны в diff построчно.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi_beacon_scanner.i18n_en import EN  # noqa: E402

PATH = os.path.join(ROOT, "contract", "i18n", "en.json")


def render() -> str:
    return json.dumps(EN, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main(argv):
    if argv and argv[0] == "check":
        with open(PATH, encoding="utf-8") as f:
            ok = f.read() == render()
        print("contract/i18n/en.json: %s" % ("совпадает" if ok else "УСТАРЕЛ (python tools/export_i18n.py)"))
        return 0 if ok else 1
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    with open(PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(render())
    print("записан contract/i18n/en.json: строк %d" % len(EN))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
