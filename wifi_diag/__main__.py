"""CLI.

  python -m wifi_diag interfaces
  python -m wifi_diag scan    --ssid CORP --save snap.json --html report.html --csv bss.csv
  python -m wifi_diag analyze snap.json --ssid CORP --html report.html
  python -m wifi_diag gui     [--ssid CORP] [--demo [snap.json]]
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import oui, report
from .model import Snapshot
from .rules import Thresholds, analyze


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wifi_diag", description="Диагностика Wi-Fi по beacon/probe IE")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--ssid", action="append", default=[],
                        help="«наш» SSID (можно несколько раз); без него анализируются все сети")
        sp.add_argument("--html", help="куда сохранить HTML-отчёт")
        sp.add_argument("--csv", help="куда сохранить CSV со списком BSS")
        sp.add_argument("--manuf", help="путь к файлу manuf (Wireshark) для определения вендора")
        sp.add_argument("--weak-rssi", type=int, default=Thresholds.weak_rssi)

    sub.add_parser("interfaces", help="показать Wi-Fi адаптеры")
    s = sub.add_parser("scan", help="просканировать эфир (только Windows)")
    s.add_argument("--interface", type=int, default=0, help="индекс адаптера из команды interfaces")
    s.add_argument("--wait", type=float, default=5.0, help="сколько секунд ждать результаты скана")
    s.add_argument("--save", help="сохранить сырой снапшот в JSON (можно потом разобрать на любой ОС)")
    common(s)
    g = sub.add_parser("gui", help="запустить приложение с окном (локальный веб-интерфейс)")
    g.add_argument("--ssid", action="append", default=[], help="«наш» SSID (можно несколько раз)")
    g.add_argument("--manuf", help="путь к файлу manuf (Wireshark)")
    g.add_argument("--demo", nargs="?", const="", metavar="SNAPSHOT",
                   help="демо-режим без сканирования; можно указать свой snap.json")
    g.add_argument("--port", type=int, default=0, help="порт (по умолчанию случайный свободный)")
    g.add_argument("--no-browser", action="store_true", help="не открывать окно, только напечатать адрес")
    a = sub.add_parser("analyze", help="разобрать ранее сохранённый снапшот")
    a.add_argument("snapshot")
    common(a)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "gui":
        from . import backends
        from .web.server import serve
        from .web.state import AppState, default_prefs_path
        if args.demo is not None:
            base = None
            if args.demo:
                with open(args.demo, "r", encoding="utf-8") as f:
                    base = Snapshot.from_json(f.read())
            backend = backends.DemoBackend(base)
        else:
            backend = backends.default_backend()
        db = oui.load_default(args.manuf)
        if db is None:
            print("предупреждение: файл manuf не найден, вендоры не определяются (укажи --manuf)", file=sys.stderr)
        serve(AppState(backend, db, args.ssid, prefs_path=default_prefs_path()), port=args.port,
              open_browser=not args.no_browser)
        return 0

    if args.cmd == "interfaces":
        from . import scanner_win
        for i, (desc, _guid) in enumerate(scanner_win.list_interfaces()):
            print("%d: %s" % (i, desc))
        return 0

    if args.cmd == "scan":
        from . import scanner_win
        snap = scanner_win.scan(args.interface, args.wait)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as f:
                f.write(snap.to_json())
            print("снапшот сохранён: %s" % args.save)
    else:
        with open(args.snapshot, "r", encoding="utf-8") as f:
            snap = Snapshot.from_json(f.read())

    db = oui.load_default(args.manuf)
    if db is None:
        print("предупреждение: файл manuf не найден, вендоры не определяются (укажи --manuf)", file=sys.stderr)
    else:
        for b in snap.bss:
            b.vendor = db.lookup(b.bssid)

    th = Thresholds(weak_rssi=args.weak_rssi)
    findings = analyze(snap.bss, th, args.ssid)
    print("BSS в эфире: %d" % len(snap.bss))
    print(report.console_summary(findings))
    if args.html:
        report.write_html(args.html, snap, findings, args.ssid)
        print("HTML-отчёт: %s" % args.html)
    if args.csv:
        report.write_csv(args.csv, snap.bss)
        print("CSV: %s" % args.csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
