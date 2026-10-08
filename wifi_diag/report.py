"""Экспорт: HTML-отчёт (он же основа PDF), Excel, CSV со списком BSS, текстовая сводка для консоли."""
from __future__ import annotations

import csv
import html
import io
from datetime import datetime
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence

from .model import Bss, Snapshot
from .rules import CRITICAL, INFO, WARNING, Finding

SEV_RU = {CRITICAL: "Критично", WARNING: "Внимание", INFO: "Информация"}

CSV_COLUMNS = [
    "ssid", "bssid", "vendor", "band_ghz", "channel", "width_mhz", "rssi_dbm", "link_quality",
    "security", "ciphers", "generation", "streams", "dot11k", "dot11r", "dot11v",
    "util_pct", "stations", "country", "beacon_interval", "dtim",
]


def _row(b: Bss) -> List[object]:
    i = b.info
    return [
        b.ssid_display, b.bssid, b.vendor or "", b.band, b.channel, i.width_mhz, b.rssi, b.link_quality,
        b.security, "/".join(b.ciphers), b.generation_label, i.max_streams or "",
        "yes" if i.dot11k else "no", "yes" if i.dot11r else "no", "yes" if i.dot11v else "no",
        "" if i.qbss_util_pct is None else i.qbss_util_pct,
        "" if i.qbss_stations is None else i.qbss_stations,
        i.country or "", b.beacon_interval, "" if i.dtim_period is None else i.dtim_period,
    ]


def render_csv(bss: Sequence[Bss]) -> str:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for b in sorted(bss, key=lambda x: (x.ssid_display.lower(), x.band, x.channel, -x.rssi)):
        w.writerow(_row(b))
    return buf.getvalue()


def write_csv(path: str, bss: Sequence[Bss]) -> None:
    # utf-8-sig, чтобы Excel на Windows сразу открыл кириллицу правильно
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        f.write(render_csv(bss))


def console_summary(findings: Sequence[Finding]) -> str:
    c = Counter(f.severity for f in findings)
    lines = ["Найдено: %d критичных, %d предупреждений, %d информационных"
             % (c[CRITICAL], c[WARNING], c[INFO])]
    for f in findings:
        lines.append("[%s] %s: %s" % (SEV_RU[f.severity], f.title, f.detail))
    return "\n".join(lines)


_CSS = """
:root{--bg:#fff;--fg:#1c1f23;--mut:#5c6670;--line:#d9dee3;--card:#f6f8fa;
--crit:#b3261e;--warn:#9a5b00;--info:#2457a6}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e9ec;--mut:#9aa5b0;--line:#2c333a;--card:#1b2025;
--crit:#ff8a80;--warn:#ffb74d;--info:#8ab4f8}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1200px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.mut{color:var(--mut)}
.sum{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.sum div{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:120px}
.sum b{display:block;font-size:24px}
.f{border:1px solid var(--line);border-left-width:4px;border-radius:6px;background:var(--card);padding:10px 14px;margin:8px 0}
.f.critical{border-left-color:var(--crit)}.f.warning{border-left-color:var(--warn)}.f.info{border-left-color:var(--info)}
.f h3{margin:0 0 2px;font-size:15px}.tag{font-size:12px;font-weight:600}
.critical .tag{color:var(--crit)}.warning .tag{color:var(--warn)}.info .tag{color:var(--info)}
.rec{margin-top:4px}code{font-size:12px;color:var(--mut)}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{position:sticky;top:0;background:var(--card)}
.ubar{display:inline-block;width:160px;height:10px;background:var(--line);border-radius:3px;overflow:hidden;vertical-align:middle}
.ubar i{display:block;height:100%}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px}
.kv dt{color:var(--mut)}.kv dd{margin:0}
@page{size:A4 landscape;margin:12mm}
@media print{
  :root{--bg:#fff;--fg:#1c1f23;--mut:#5c6670;--line:#d9dee3;--card:#f6f8fa;--crit:#b3261e;--warn:#9a5b00;--info:#2457a6}
  body{padding:0;font-size:11px}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  h2{break-after:avoid}.f,tr{break-inside:avoid}table{font-size:10px}th{position:static}
  .wrap{overflow:visible}td,th{white-space:normal}
}
"""

JOURNAL_KIND_RU = {
    "connected": "подключение", "disconnected": "обрыв", "roam": "роуминг", "ssid_change": "смена сети",
    "pingpong": "пинг-понг", "sticky": "залипание", "attempt_fail": "неудачное подключение",
    "disconnect_reason": "отключение (по данным Windows)",
}

def util_color(u: float) -> str:
    hue = round(130 * (1 - max(0.0, min(1.0, u / 75.0))))
    return "hsl(%d 70%% 40%%)" % hue


def survey_rows(points: Sequence[Dict[str, Any]], focus: Sequence[str]) -> List[List[Any]]:
    """Таблица точек обхода: для каждого «моего» SSID лучший сигнал и сколько его BSS слышно от −75."""
    names = list(focus) or ["(все сети)"]
    head = ["Точка", "X, %", "Y, %", "Время", "Статус", "Подключение", "RSSI подключения"]
    for n in names:
        head += ["Лучший RSSI: %s" % n, "BSS от −75: %s" % n]
    rows: List[List[Any]] = [head]
    for p in points:
        res = p.get("results") or {}
        c = p.get("conn") or {}
        r: List[Any] = [p["id"], round(p["x"] * 100, 1), round(p["y"] * 100, 1),
                        datetime.fromtimestamp(p["t"]).strftime("%Y-%m-%d %H:%M:%S") if p.get("t") else "",
                        {"done": "готово", "pending": "ожидает скан", "failed": "ошибка"}.get(p.get("status"), ""),
                        ("%s %s" % (c.get("ssid", ""), c.get("bssid", ""))).strip(), c.get("rssi")]
        for n in names:
            vals = [v[3] for v in res.values() if focus == [] or v[0] == n]
            r += [max(vals) if vals else None, sum(1 for v in vals if v >= -75)]
        rows.append(r)
    return rows


_TABLE_COLS = [
    ("SSID", lambda b: b.ssid_display), ("BSSID", lambda b: b.bssid), ("Вендор", lambda b: b.vendor or ""),
    ("ГГц", lambda b: b.band), ("Канал", lambda b: b.channel), ("Ширина", lambda b: b.info.width_mhz),
    ("RSSI", lambda b: b.rssi), ("Безопасность", lambda b: b.security), ("Поколение", lambda b: b.generation_label),
    ("k", lambda b: "+" if b.info.dot11k else "-"), ("r", lambda b: "+" if b.info.dot11r else "-"),
    ("v", lambda b: "+" if b.info.dot11v else "-"),
    ("Загрузка", lambda b: "" if b.info.qbss_util_pct is None else "%.0f%%" % b.info.qbss_util_pct),
    ("Станций", lambda b: "" if b.info.qbss_stations is None else b.info.qbss_stations),
    ("Страна", lambda b: b.info.country or ""),
]


def render_html(snap: Snapshot, findings: Sequence[Finding], focus: Sequence[str], scope_note: str = "",
                util: Optional[Dict[str, Any]] = None, journal: Optional[Dict[str, Any]] = None,
                survey: Optional[Sequence[Dict[str, Any]]] = None) -> str:
    e = html.escape
    c = Counter(f.severity for f in findings)
    out: List[str] = []
    out.append("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
               "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
               "<meta name='viewport' content='width=device-width,initial-scale=1'>"
               "<title>Wi-Fi: отчёт диагностики</title><style>%s</style></head><body><main>" % _CSS)
    out.append("<h1>Wi-Fi: отчёт диагностики</h1>")
    out.append("<div class='mut'>Снято: %s · адаптер: %s · BSS в отчёте: %d%s</div>" % (
        e(snap.taken_at), e(snap.interface or "-"), len(snap.bss),
        (" · мои SSID: " + e(", ".join(focus))) if focus else ""))
    if scope_note:
        out.append("<div class='mut'>В отчёт включены: %s</div>" % e(scope_note))
    ssids = len({b.ssid_display for b in snap.bss if not b.hidden})
    out.append("<div class='sum'><div><b>%d</b>BSS</div><div><b>%d</b>SSID</div>"
               "<div><b>%d</b>Критично</div><div><b>%d</b>Внимание</div><div><b>%d</b>Информация</div></div>"
               % (len(snap.bss), ssids, c[CRITICAL], c[WARNING], c[INFO]))
    out.append("<h2>Находки</h2>")
    if not findings:
        out.append("<p class='mut'>Проблем по заданным правилам не найдено.</p>")
    for f in findings:
        out.append("<div class='f %s'><span class='tag'>%s · %s</span><h3>%s</h3><div>%s</div>"
                   % (f.severity, SEV_RU[f.severity], e(f.code), e(f.title), e(f.detail)))
        if f.recommendation:
            out.append("<div class='rec'><b>Что проверить:</b> %s</div>" % e(f.recommendation))
        if f.bssids:
            shown = f.bssids[:8]
            more = " … (+%d)" % (len(f.bssids) - 8) if len(f.bssids) > 8 else ""
            out.append("<code>%s%s</code>" % (e(", ".join(shown)), more))
        out.append("</div>")
    if util and util.get("channels"):
        out.append("<h2>Загрузка каналов (QBSS Load)</h2><p class='mut'>Доля времени, когда сама AP считает канал занятым; "
                   "на канал взят максимум среди AP, сообщающих эту цифру.</p>")
        out.append("<div class='wrap'><table><thead><tr><th>ГГц</th><th>Канал</th><th>Загрузка</th><th></th><th>Уровень</th>"
                   "<th>Среднее</th><th>AP с данными</th><th>Станций</th><th>Самые загруженные</th></tr></thead><tbody>")
        for ch in util["channels"]:
            top = ", ".join("%s %.0f%%" % (a["ssid"], a["util"]) for a in ch["aps"][:3])
            out.append("<tr><td>%s</td><td>%s</td><td><span class='ubar'><i style='width:%.0f%%;background:%s'></i></span></td>"
                       "<td>%.0f%%</td><td>%s</td><td>%.0f%%</td><td>%d из %d</td><td>%d</td><td>%s</td></tr>"
                       % (e(ch["band"]), ch["channel"], max(ch["max"], 1), util_color(ch["max"]), ch["max"],
                          e(ch["label"]), ch["avg"], ch["reporting"], ch["bss"],
                          ch["stations"], e(top)))
        out.append("</tbody></table></div>")
        if util.get("no_data"):
            out.append("<p class='mut'>Нет данных QBSS Load: %s.</p>" % e(", ".join(
                "%s ГГц канал %s" % (x["band"], x["channel"]) for x in util["no_data"])))
    if journal and journal.get("events"):
        st = journal.get("stats", {})
        out.append("<h2>Подключение ноутбука</h2>")
        out.append("<dl class='kv'><dt>Роумингов</dt><dd>%d</dd><dt>Обрывов</dt><dd>%d (без связи %.0f с)</dd>"
                   "<dt>Пинг-понгов</dt><dd>%d</dd><dt>Залипаний</dt><dd>%d</dd><dt>Неудачных подключений</dt><dd>%d</dd></dl>"
                   % (st.get("roams", 0), st.get("disconnects", 0), st.get("down_s", 0), st.get("pingpong", 0),
                      st.get("sticky", 0), st.get("attempt_fail", 0)))
        out.append("<div class='wrap'><table><thead><tr><th>Время</th><th>Событие</th><th>SSID</th><th>Откуда</th><th>Куда</th>"
                   "<th>RSSI</th><th>Длительность</th><th>Причина</th></tr></thead><tbody>")
        for ev in list(journal["events"])[-200:][::-1]:
            rs = " → ".join(str(x) for x in (ev["rssi_from"], ev["rssi_to"]) if x is not None)
            out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                datetime.fromtimestamp(ev["t"]).strftime("%H:%M:%S"), e(JOURNAL_KIND_RU.get(ev["kind"], ev["kind"])),
                e(ev["ssid"]), e(ev["bssid_from"]), e(ev["bssid_to"]), e(rs),
                "" if ev["duration_s"] is None else "%.0f с" % ev["duration_s"], e(ev["reason"])))
        out.append("</tbody></table></div>")
    if survey:
        rows = survey_rows(survey, list(focus))
        out.append("<h2>Обход: точки замеров</h2><p class='mut'>Карта покрытия сохраняется отдельно из вкладки «Обход» (PNG).</p>")
        out.append("<div class='wrap'><table><thead><tr>%s</tr></thead><tbody>" % "".join("<th>%s</th>" % e(str(h)) for h in rows[0]))
        for r in rows[1:]:
            out.append("<tr>%s</tr>" % "".join("<td>%s</td>" % e("" if v is None else str(v)) for v in r))
        out.append("</tbody></table></div>")
    out.append("<h2>Все BSS</h2><div class='wrap'><table><thead><tr>")
    out.extend("<th>%s</th>" % e(name) for name, _ in _TABLE_COLS)
    out.append("</tr></thead><tbody>")
    for b in sorted(snap.bss, key=lambda x: (x.ssid_display.lower(), x.band, x.channel, -x.rssi)):
        out.append("<tr>%s</tr>" % "".join("<td>%s</td>" % e(str(fn(b))) for _, fn in _TABLE_COLS))
    out.append("</tbody></table></div></main></body></html>")
    return "".join(out)


def build_xlsx_report(snap: Snapshot, findings: Sequence[Finding], focus: Sequence[str], scope_note: str = "",
                      util: Optional[Dict[str, Any]] = None, history: Optional[Dict[str, Any]] = None,
                      journal: Optional[Dict[str, Any]] = None,
                      survey: Optional[Sequence[Dict[str, Any]]] = None) -> bytes:
    from .xlsx import build_xlsx
    c = Counter(f.severity for f in findings)
    summary: List[List[Any]] = [["Параметр", "Значение"],
                                ["Снято", snap.taken_at], ["Адаптер", snap.interface or "-"],
                                ["В отчёт включены", scope_note or "все сети"], ["Мои SSID", ", ".join(focus) or "-"],
                                ["BSS", len(snap.bss)], ["SSID", len({b.ssid_display for b in snap.bss if not b.hidden})],
                                ["Находки: критично", c[CRITICAL]], ["Находки: внимание", c[WARNING]], ["Находки: информация", c[INFO]]]
    if journal and journal.get("events"):
        st = journal.get("stats", {})
        summary += [["Роумингов ноутбука", st.get("roams", 0)], ["Обрывов", st.get("disconnects", 0)],
                    ["Без связи, с", st.get("down_s", 0)], ["Пинг-понгов", st.get("pingpong", 0)], ["Залипаний", st.get("sticky", 0)]]
    sheets: List[Any] = [("Сводка", summary)]
    bss_rows = [CSV_COLUMNS] + [_row(b) for b in sorted(snap.bss, key=lambda x: (x.ssid_display.lower(), x.band, x.channel, -x.rssi))]
    sheets.append(("BSS", bss_rows))
    fr: List[List[Any]] = [["Важность", "Код", "Проблема", "Подробности", "Что проверить", "SSID", "BSSID"]]
    fr += [[SEV_RU[f.severity], f.code, f.title, f.detail, f.recommendation, f.ssid, ", ".join(f.bssids)] for f in findings]
    sheets.append(("Находки", fr))
    if util and util.get("channels"):
        ur: List[List[Any]] = [["ГГц", "Канал", "Загрузка макс, %", "Загрузка средн, %", "Уровень", "AP с данными", "BSS на канале",
                                "Станций", "Самые загруженные"]]
        for ch in util["channels"]:
            ur.append([ch["band"], ch["channel"], ch["max"], ch["avg"], ch["label"], ch["reporting"],
                       ch["bss"], ch["stations"], ", ".join("%s %.0f%%" % (a["ssid"], a["util"]) for a in ch["aps"][:5])])
        sheets.append(("Загрузка каналов", ur))
    if history:
        names = {b.bssid: (b.ssid_display, b.band, b.channel) for b in snap.bss}
        hr: List[List[Any]] = [["Время", "SSID", "BSSID", "ГГц", "Канал", "RSSI, дБм", "Загрузка, %"]]
        for k in sorted(history):
            n = names.get(k, ("", "", ""))
            for t, r, u in history[k]:
                hr.append([datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S"), n[0], k, n[1], n[2], r, u])
        sheets.append(("История", hr))
    if journal and journal.get("events"):
        jr: List[List[Any]] = [["Время", "Событие", "SSID", "Откуда", "Куда", "RSSI до", "RSSI после", "Длительность, с",
                                "Код причины", "Причина", "Описание"]]
        for ev in journal["events"]:
            jr.append([datetime.fromtimestamp(ev["t"]).strftime("%Y-%m-%d %H:%M:%S"), JOURNAL_KIND_RU.get(ev["kind"], ev["kind"]),
                       ev["ssid"], ev["bssid_from"], ev["bssid_to"], ev["rssi_from"], ev["rssi_to"], ev["duration_s"],
                       "0x%X" % ev["reason_code"] if ev["reason_code"] is not None else None, ev["reason"], ev["text"]])
        sheets.append(("Журнал подключения", jr))
    if survey:
        sheets.append(("Обход", survey_rows(survey, list(focus))))
    return build_xlsx(sheets)


def write_html(path: str, snap: Snapshot, findings: Sequence[Finding], focus: Sequence[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(snap, findings, focus))


def render_history_csv(history, names) -> str:
    """history: {bssid: [(t, rssi, util), ...]}; names: {bssid: (ssid, band, channel)}."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow(["time", "ssid", "bssid", "band_ghz", "channel", "rssi_dbm", "util_pct"])
    for bssid in sorted(history):
        ssid, band, ch = names.get(bssid, ("", "", ""))
        for t, r, u in history[bssid]:
            w.writerow([datetime.fromtimestamp(t).isoformat(timespec="seconds"), ssid, bssid, band, ch, r,
                        "" if u is None else u])
    return buf.getvalue()


def render_journal_csv(events) -> str:
    """events - список словарей ConnEvent (asdict)."""
    buf = io.StringIO(newline="")
    w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    w.writerow(["time", "event", "ssid", "bssid_from", "bssid_to", "rssi_from", "rssi_to", "duration_s",
                "reason_code", "reason", "text"])
    for e in events:
        w.writerow([datetime.fromtimestamp(e["t"]).isoformat(timespec="seconds"), JOURNAL_KIND_RU.get(e["kind"], e["kind"]),
                    e["ssid"], e["bssid_from"], e["bssid_to"],
                    "" if e["rssi_from"] is None else e["rssi_from"], "" if e["rssi_to"] is None else e["rssi_to"],
                    "" if e["duration_s"] is None else e["duration_s"],
                    "" if e["reason_code"] is None else "0x%X" % e["reason_code"], e["reason"], e["text"]])
    return buf.getvalue()
