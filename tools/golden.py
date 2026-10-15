"""Эталоны контракта: что программа выдаёт на фиксированных снапшотах.

    python tools/golden.py check     - пересчитать и сравнить с contract/golden (ничего не пишет)
    python tools/golden.py update    - перезаписать contract/golden (только если изменение задумано!)
    python tools/golden.py diff      - показать, чем пересчёт отличается от эталона

Зачем: это «договор» между реализациями. Python 1.x и будущая версия на Rust на одних и тех же
contract/fixtures/*.json должны выдавать одно и то же: разбор каждого BSS (то, что видит таблица и вкладка
Beacon), проблемы, свободность каналов, загрузку каналов - на русском и на английском.
Формат эталона описан в contract/schema/golden.schema.json, правила - в contract/README.md.

Числа сравниваются с допуском 1e-6: дробные значения (дБм, проценты) уже округлены программой,
допуск нужен только против разницы в последнем бите между платформами.
"""
from __future__ import annotations

import json
import math
import os
import sys
from dataclasses import asdict
from typing import Any, Dict, List

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wifi_beacon_scanner import i18n  # noqa: E402
from wifi_beacon_scanner.model import Snapshot  # noqa: E402
from wifi_beacon_scanner.rules import analyze, channel_advice, channel_utilization  # noqa: E402
from wifi_beacon_scanner.web.state import bss_to_dict  # noqa: E402

CONTRACT = os.path.join(ROOT, "contract")
FIXTURES = os.path.join(CONTRACT, "fixtures")
GOLDEN = os.path.join(CONTRACT, "golden")
SCHEMA = os.path.join(CONTRACT, "schema", "golden.schema.json")
CONTRACT_VERSION = 1
LANGS = ("ru", "en")
FLOAT_TOL = 1e-6


def fixtures() -> List[str]:
    return sorted(f[:-5] for f in os.listdir(FIXTURES) if f.endswith(".json"))


def compute(name: str, lang: str) -> Dict[str, Any]:
    """Эталон для одного снапшота на одном языке. Язык программы возвращается как был."""
    with open(os.path.join(FIXTURES, name + ".json"), encoding="utf-8") as f:
        snap = Snapshot.from_json(f.read())
    prev = i18n.get_lang()
    i18n.set_lang(lang)
    try:
        return {
            "contract": CONTRACT_VERSION,
            "fixture": name,
            "lang": lang,
            "bss": [bss_to_dict(b) for b in snap.bss],
            "findings": [asdict(f) for f in analyze(snap.bss)],
            "advice": {band: channel_advice(snap.bss, band) for band in ("2.4", "5")},
            "util": channel_utilization(snap.bss),
        }
    finally:
        i18n.set_lang(prev)


def golden_path(name: str, lang: str) -> str:
    return os.path.join(GOLDEN, "%s.%s.json" % (name, lang))


def dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=1) + "\n"


# ---------------------------------------------------------------- сравнение
def differences(a: Any, b: Any, path: str = "") -> List[str]:
    """Список отличий b от a (a - эталон). Пустой список - совпадает."""
    num = (int, float)
    if isinstance(a, bool) or isinstance(b, bool):
        return [] if a is b else ["%s: %r -> %r" % (path or "/", a, b)]
    if isinstance(a, num) and isinstance(b, num):
        if math.isclose(float(a), float(b), rel_tol=0, abs_tol=FLOAT_TOL):
            return []
        return ["%s: %r -> %r" % (path or "/", a, b)]
    if type(a) is not type(b):
        return ["%s: тип %s -> %s (%r -> %r)" % (path or "/", type(a).__name__, type(b).__name__, a, b)]
    if isinstance(a, dict):
        out = []
        for k in a:
            if k not in b:
                out.append("%s/%s: пропало" % (path, k))
            else:
                out += differences(a[k], b[k], "%s/%s" % (path, k))
        out += ["%s/%s: новое поле" % (path, k) for k in b if k not in a]
        return out
    if isinstance(a, list):
        out = []
        if len(a) != len(b):
            out.append("%s: длина %d -> %d" % (path or "/", len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            out += differences(x, y, "%s[%d]" % (path, i))
        return out
    return [] if a == b else ["%s: %r -> %r" % (path or "/", a, b)]


# ---------------------------------------------------------------- схема (подмножество JSON Schema)
def validate(obj: Any, schema: Dict[str, Any], root: Dict[str, Any] = None, path: str = "") -> List[str]:
    """Проверка по подмножеству JSON Schema 2020-12: $ref, type, properties, required,
    additionalProperties (false / схема), items, enum, prefixItems. Внешних библиотек не нужно."""
    root = root or schema
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/$defs/"), ref
        return validate(obj, root["$defs"][ref[len("#/$defs/"):]], root, path)
    errs: List[str] = []
    types = schema.get("type")
    if types is not None:
        types = [types] if isinstance(types, str) else types
        ok = any(_is_type(obj, t) for t in types)
        if not ok:
            return ["%s: ожидался тип %s, получено %r" % (path or "/", "|".join(types), obj)]
    if "enum" in schema and obj not in schema["enum"]:
        errs.append("%s: %r не из %r" % (path or "/", obj, schema["enum"]))
    if isinstance(obj, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in obj:
                errs.append("%s: нет обязательного поля %s" % (path or "/", k))
        extra = schema.get("additionalProperties", True)
        for k, v in obj.items():
            if k in props:
                errs += validate(v, props[k], root, "%s/%s" % (path, k))
            elif extra is False:
                errs.append("%s: лишнее поле %s" % (path or "/", k))
            elif isinstance(extra, dict):
                errs += validate(v, extra, root, "%s/%s" % (path, k))
    if isinstance(obj, list):
        pref = schema.get("prefixItems")
        if pref is not None:
            if len(obj) != len(pref):
                errs.append("%s: ожидалось %d элементов, получено %d" % (path or "/", len(pref), len(obj)))
            for i, (x, s) in enumerate(zip(obj, pref)):
                errs += validate(x, s, root, "%s[%d]" % (path, i))
        elif "items" in schema:
            for i, x in enumerate(obj):
                errs += validate(x, schema["items"], root, "%s[%d]" % (path, i))
    return errs


def _is_type(v: Any, t: str) -> bool:
    if t == "null":
        return v is None
    if t == "boolean":
        return isinstance(v, bool)
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "string":
        return isinstance(v, str)
    if t == "array":
        return isinstance(v, list)
    if t == "object":
        return isinstance(v, dict)
    raise ValueError("неизвестный тип в схеме: %s" % t)


def load_schema() -> Dict[str, Any]:
    with open(SCHEMA, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------- команды
def check(verbose: bool = False) -> List[str]:
    """Все проблемы: нет эталона, расхождение с пересчётом, нарушение схемы. Пусто - всё хорошо."""
    schema = load_schema()
    problems: List[str] = []
    for name in fixtures():
        for lang in LANGS:
            p = golden_path(name, lang)
            if not os.path.exists(p):
                problems.append("%s.%s: нет эталона (python tools/golden.py update)" % (name, lang))
                continue
            with open(p, encoding="utf-8") as f:
                want = json.load(f)
            got = json.loads(dump(compute(name, lang)))     # через JSON: те же типы, что в файле
            for e in validate(want, schema):
                problems.append("%s.%s: схема: %s" % (name, lang, e))
            diff = differences(want, got)
            if diff:
                problems.append("%s.%s: отличий от эталона %d" % (name, lang, len(diff)))
                if verbose:
                    problems += ["    " + d for d in diff[:40]]
    return problems


def update() -> None:
    os.makedirs(GOLDEN, exist_ok=True)
    schema = load_schema()
    for name in fixtures():
        for lang in LANGS:
            data = compute(name, lang)
            errs = validate(json.loads(dump(data)), schema)
            if errs:
                raise SystemExit("%s.%s не проходит схему:\n  %s" % (name, lang, "\n  ".join(errs[:20])))
            with open(golden_path(name, lang), "w", encoding="utf-8", newline="\n") as f:
                f.write(dump(data))
            print("записан %s" % os.path.relpath(golden_path(name, lang), ROOT))


def main(argv: List[str]) -> int:
    cmd = argv[0] if argv else "check"
    if cmd == "update":
        update()
        return 0
    if cmd in ("check", "diff"):
        problems = check(verbose=cmd == "diff")
        for p in problems:
            print(p)
        print("эталоны: %s" % ("совпадают" if not problems else "ЕСТЬ ОТЛИЧИЯ"))
        return 1 if problems else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
