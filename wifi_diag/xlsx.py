"""Минимальная запись .xlsx без зависимостей (Office Open XML: zip с XML внутри).

Умеет то, что нужно для отчёта: несколько листов, строка заголовка жирным с заливкой, закреплённая
первая строка, автофильтр, ширина колонок по содержимому. Строки пишутся как inline strings.
Из текста вырезаются символы, недопустимые в XML: SSID приходят из эфира и могут содержать что угодно.

Колонки сигнала и загрузки получают цветовую шкалу (условное форматирование, Excel пересчитывает его сам):
RSSI от красного (−85 и ниже) через жёлтый (−67) к зелёному (−50 и выше), загрузка наоборот: 0% зелёный,
50% жёлтый, от 75% красный. Колонка определяется по заголовку.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any, List, Sequence, Tuple
from xml.sax.saxutils import escape

_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff￾￿]")
_BAD_SHEET = re.compile(r"[\[\]:*?/\\]")

Sheet = Tuple[str, Sequence[Sequence[Any]]]     # (имя, строки; первая строка - заголовок)


def _col(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _text(v: Any) -> str:
    return escape(_BAD_XML.sub("", str(v)))


def _cell(ref: str, v: Any, style: int) -> str:
    st = ' s="%d"' % style if style else ""
    if v is None or v == "":
        return '<c r="%s"%s/>' % (ref, st) if style else ""
    if isinstance(v, bool):
        v = "да" if v else "нет"
    if isinstance(v, (int, float)) and v == v and abs(v) != float("inf"):
        return '<c r="%s"%s><v>%s</v></c>' % (ref, st, repr(v) if isinstance(v, float) else v)
    return '<c r="%s" t="inlineStr"%s><is><t xml:space="preserve">%s</t></is></c>' % (ref, st, _text(v))


RED, YELLOW, GREEN = "FFF8696B", "FFFFEB84", "FF63BE7B"
# (признак в заголовке, точки шкалы, цвета)
SCALES = [
    (re.compile(r"rssi", re.I), ("-85", "-67", "-50"), (RED, YELLOW, GREEN)),
    (re.compile(r"загрузка|util", re.I), ("0", "50", "75"), (GREEN, YELLOW, RED)),
]


def scale_for(header: Any):
    h = str(header or "")
    for rx, pts, cols in SCALES:
        if rx.search(h):
            return pts, cols
    return None


def _scales_xml(rows: Sequence[Sequence[Any]]) -> str:
    if len(rows) < 2:
        return ""
    out, prio = [], 1
    for ci, h in enumerate(rows[0]):
        sc = scale_for(h)
        if not sc:
            continue
        pts, cols = sc
        ref = "%s2:%s%d" % (_col(ci), _col(ci), len(rows))
        out.append('<conditionalFormatting sqref="%s"><cfRule type="colorScale" priority="%d"><colorScale>%s%s</colorScale>'
                   '</cfRule></conditionalFormatting>' % (ref, prio, "".join('<cfvo type="num" val="%s"/>' % p for p in pts),
                                                          "".join('<color rgb="%s"/>' % c for c in cols)))
        prio += 1
    return "".join(out)


def _sheet_xml(rows: Sequence[Sequence[Any]]) -> str:
    ncols = max((len(r) for r in rows), default=0)
    widths = [8] * ncols
    for r in rows[:2000]:
        for i, v in enumerate(r):
            widths[i] = max(widths[i], min(60, len(str(v)) + 2) if v is not None else 0)
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    if rows:
        out.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
                   'state="frozen"/></sheetView></sheetViews>')
    if ncols:
        out.append("<cols>%s</cols>" % "".join('<col min="%d" max="%d" width="%d" customWidth="1"/>' % (i + 1, i + 1, w)
                                               for i, w in enumerate(widths)))
    out.append("<sheetData>")
    for ri, r in enumerate(rows):
        cells = "".join(_cell("%s%d" % (_col(ci), ri + 1), v, 1 if ri == 0 else 0) for ci, v in enumerate(r))
        out.append('<row r="%d">%s</row>' % (ri + 1, cells))
    out.append("</sheetData>")
    if len(rows) > 1 and ncols:
        out.append('<autoFilter ref="A1:%s%d"/>' % (_col(ncols - 1), len(rows)))
        out.append(_scales_xml(rows))
    out.append("</worksheet>")
    return "".join(out)


def _sheet_names(names: List[str]) -> List[str]:
    used, out = set(), []
    for n in names:
        base = (_BAD_SHEET.sub("_", _BAD_XML.sub("", n)).strip() or "Лист")[:31]
        cand, k = base, 2
        while cand.lower() in used:
            suf = " (%d)" % k
            cand, k = base[:31 - len(suf)] + suf, k + 1
        used.add(cand.lower())
        out.append(cand)
    return out


_STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
           '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
           '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
           '<fill><patternFill patternType="solid"><fgColor rgb="FFDDE7EE"/><bgColor indexed="64"/></patternFill></fill></fills>'
           '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
           '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
           '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
           '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
           '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')


def build_xlsx(sheets: Sequence[Sheet]) -> bytes:
    if not sheets:
        raise ValueError("нет листов")
    names = _sheet_names([n for n, _ in sheets])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                   + "".join('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % (i + 1)
                             for i in range(len(sheets)))
                   + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   '</Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (escape(n, {'"': "&quot;"}), i + 1, i + 1)
                             for i, n in enumerate(names))
                   + "</sheets></workbook>")
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i + 1, i + 1)
                             for i in range(len(sheets)))
                   + '<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>' % (len(sheets) + 1)
                   + "</Relationships>")
        z.writestr("xl/styles.xml", _STYLES)
        for i, (_, rows) in enumerate(sheets):
            z.writestr("xl/worksheets/sheet%d.xml" % (i + 1), _sheet_xml(rows))
    return buf.getvalue()
