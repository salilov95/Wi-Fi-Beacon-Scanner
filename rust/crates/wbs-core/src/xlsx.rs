//! Минимальная запись .xlsx без зависимостей (Office Open XML: zip с XML внутри). Перенос `wifi_beacon_scanner/xlsx.py`.
//!
//! Несколько листов, строка заголовка жирным с заливкой, закреплённая первая строка, автофильтр, ширина колонок
//! по содержимому, строки - inline strings. Колонки сигнала и загрузки получают цветовую шкалу (условное
//! форматирование): RSSI от красного (−85) через жёлтый (−67) к зелёному (−50), загрузка наоборот (0/50/75%).
//! XML частей совпадает с 1.x; zip - без сжатия (Excel читает такой так же).

use crate::i18n::{py_float, tr};
use crate::report::Cell;

/// (имя листа, строки; первая строка - заголовок)
pub type Sheet = (String, Vec<Vec<Cell>>);

/// Символы, недопустимые в XML (SSID приходят из эфира и могут содержать что угодно).
fn strip_bad(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            let u = c as u32;
            !(u <= 0x08 || u == 0x0B || u == 0x0C || (0x0E..=0x1F).contains(&u) || u == 0xFFFE || u == 0xFFFF)
        })
        .collect()
}

/// `xml.sax.saxutils.escape`: & < >.
fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Номер колонки -> буквы (0 -> A, 26 -> AA).
pub fn col(n: usize) -> String {
    let mut s = Vec::new();
    let mut n = n + 1;
    while n > 0 {
        let r = (n - 1) % 26;
        n = (n - 1) / 26;
        s.push(b'A' + r as u8);
    }
    s.reverse();
    String::from_utf8(s).unwrap_or_default()
}

fn cell(r: &str, v: &Cell, style: u8) -> String {
    let st = if style > 0 {
        format!(" s=\"{style}\"")
    } else {
        String::new()
    };
    let text = match v {
        Cell::Empty => {
            return if style > 0 {
                format!("<c r=\"{r}\"{st}/>")
            } else {
                String::new()
            }
        }
        Cell::Str(s) if s.is_empty() => {
            return if style > 0 {
                format!("<c r=\"{r}\"{st}/>")
            } else {
                String::new()
            }
        }
        Cell::Bool(b) => tr(if *b { "да" } else { "нет" }),
        Cell::Int(n) => return format!("<c r=\"{r}\"{st}><v>{n}</v></c>"),
        Cell::Num(x) if x.is_finite() => return format!("<c r=\"{r}\"{st}><v>{}</v></c>", py_float(*x)),
        other => other.text(),
    };
    format!(
        "<c r=\"{r}\" t=\"inlineStr\"{st}><is><t xml:space=\"preserve\">{}</t></is></c>",
        escape(&strip_bad(&text))
    )
}

const RED: &str = "FFF8696B";
const YELLOW: &str = "FFFFEB84";
const GREEN: &str = "FF63BE7B";

/// Шкала по заголовку колонки: точки и цвета.
pub fn scale_for(header: &str) -> Option<([&'static str; 3], [&'static str; 3])> {
    let h = header.to_lowercase();
    if h.contains("rssi") {
        return Some((["-85", "-67", "-50"], [RED, YELLOW, GREEN]));
    }
    if h.contains("загрузка") || h.contains("util") || h.contains("load") {
        return Some((["0", "50", "75"], [GREEN, YELLOW, RED]));
    }
    None
}

fn scales_xml(rows: &[Vec<Cell>]) -> String {
    if rows.len() < 2 {
        return String::new();
    }
    let mut out = String::new();
    let mut prio = 1;
    for (ci, h) in rows[0].iter().enumerate() {
        let Some((pts, cols)) = scale_for(&h.text()) else {
            continue;
        };
        let c = col(ci);
        out.push_str(&format!(
            "<conditionalFormatting sqref=\"{c}2:{c}{}\"><cfRule type=\"colorScale\" priority=\"{prio}\"><colorScale>{}{}</colorScale></cfRule></conditionalFormatting>",
            rows.len(),
            pts.iter().map(|p| format!("<cfvo type=\"num\" val=\"{p}\"/>")).collect::<String>(),
            cols.iter().map(|c| format!("<color rgb=\"{c}\"/>")).collect::<String>(),
        ));
        prio += 1;
    }
    out
}

/// XML листа (`_sheet_xml`).
pub fn sheet_xml(rows: &[Vec<Cell>]) -> String {
    let ncols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut widths = vec![8usize; ncols];
    for r in rows.iter().take(2000) {
        for (i, v) in r.iter().enumerate() {
            let w = match v {
                Cell::Empty => 0,
                _ => (v.text().chars().count() + 2).min(60),
            };
            widths[i] = widths[i].max(w);
        }
    }
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">",
    );
    if !rows.is_empty() {
        out.push_str("<sheetViews><sheetView workbookViewId=\"0\"><pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/></sheetView></sheetViews>");
    }
    if ncols > 0 {
        out.push_str("<cols>");
        for (i, w) in widths.iter().enumerate() {
            out.push_str(&format!(
                "<col min=\"{0}\" max=\"{0}\" width=\"{w}\" customWidth=\"1\"/>",
                i + 1
            ));
        }
        out.push_str("</cols>");
    }
    out.push_str("<sheetData>");
    for (ri, r) in rows.iter().enumerate() {
        let cells: String = r
            .iter()
            .enumerate()
            .map(|(ci, v)| cell(&format!("{}{}", col(ci), ri + 1), v, if ri == 0 { 1 } else { 0 }))
            .collect();
        out.push_str(&format!("<row r=\"{}\">{cells}</row>", ri + 1));
    }
    out.push_str("</sheetData>");
    if rows.len() > 1 && ncols > 0 {
        out.push_str(&format!("<autoFilter ref=\"A1:{}{}\"/>", col(ncols - 1), rows.len()));
        out.push_str(&scales_xml(rows));
    }
    out.push_str("</worksheet>");
    out
}

/// Имена листов: без запрещённых символов, до 31 символа, без повторов (`_sheet_names`).
pub fn sheet_names(names: &[String]) -> Vec<String> {
    let mut used: Vec<String> = vec![];
    let mut out = vec![];
    for n in names {
        let cleaned: String = strip_bad(n)
            .chars()
            .map(|c| if "[]:*?/\\".contains(c) { '_' } else { c })
            .collect();
        let trimmed = cleaned.trim();
        let base: String = if trimmed.is_empty() {
            tr("Лист")
        } else {
            trimmed.to_string()
        }
        .chars()
        .take(31)
        .collect();
        let (mut cand, mut k) = (base.clone(), 2);
        while used.contains(&cand.to_lowercase()) {
            let suf = format!(" ({k})");
            let keep = 31usize.saturating_sub(suf.chars().count());
            cand = base.chars().take(keep).collect::<String>() + &suf;
            k += 1;
        }
        used.push(cand.to_lowercase());
        out.push(cand);
    }
    out
}

const STYLES: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<styleSheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">",
    "<fonts count=\"2\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font>",
    "<font><b/><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts>",
    "<fills count=\"3\"><fill><patternFill patternType=\"none\"/></fill><fill><patternFill patternType=\"gray125\"/></fill>",
    "<fill><patternFill patternType=\"solid\"><fgColor rgb=\"FFDDE7EE\"/><bgColor indexed=\"64\"/></patternFill></fill></fills>",
    "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>",
    "<cellStyleXfs count=\"1\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\"/></cellStyleXfs>",
    "<cellXfs count=\"2\"><xf numFmtId=\"0\" fontId=\"0\" fillId=\"0\" borderId=\"0\" xfId=\"0\"/>",
    "<xf numFmtId=\"0\" fontId=\"1\" fillId=\"2\" borderId=\"0\" xfId=\"0\" applyFont=\"1\" applyFill=\"1\"/></cellXfs>",
    "<cellStyles count=\"1\"><cellStyle name=\"Normal\" xfId=\"0\" builtinId=\"0\"/></cellStyles></styleSheet>"
);

const XML_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";

/// Части книги: (путь в zip, содержимое) - в том же порядке, что пишет 1.x.
pub fn parts(sheets: &[Sheet]) -> Result<Vec<(String, String)>, String> {
    if sheets.is_empty() {
        return Err(tr("нет листов"));
    }
    let names = sheet_names(&sheets.iter().map(|s| s.0.clone()).collect::<Vec<_>>());
    let n = sheets.len();
    let mut out = vec![];
    let mut ct = format!("{XML_HEAD}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>");
    for i in 1..=n {
        ct.push_str(&format!("<Override PartName=\"/xl/worksheets/sheet{i}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"));
    }
    ct.push_str("</Types>");
    out.push(("[Content_Types].xml".to_string(), ct));
    out.push((
        "_rels/.rels".into(),
        format!("{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>"),
    ));
    let mut wb = format!("{XML_HEAD}<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets>");
    for (i, name) in names.iter().enumerate() {
        wb.push_str(&format!(
            "<sheet name=\"{}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
            escape(name).replace('"', "&quot;"),
            i + 1,
            i + 1
        ));
    }
    wb.push_str("</sheets></workbook>");
    out.push(("xl/workbook.xml".into(), wb));
    let mut rels =
        format!("{XML_HEAD}<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">");
    for i in 1..=n {
        rels.push_str(&format!("<Relationship Id=\"rId{i}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{i}.xml\"/>"));
    }
    rels.push_str(&format!("<Relationship Id=\"rId{}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>", n + 1));
    out.push(("xl/_rels/workbook.xml.rels".into(), rels));
    out.push(("xl/styles.xml".into(), STYLES.into()));
    for (i, (_, rows)) in sheets.iter().enumerate() {
        out.push((format!("xl/worksheets/sheet{}.xml", i + 1), sheet_xml(rows)));
    }
    Ok(out)
}

/// Книга .xlsx.
pub fn build_xlsx(sheets: &[Sheet]) -> Result<Vec<u8>, String> {
    let files: Vec<(String, Vec<u8>)> = parts(sheets)?.into_iter().map(|(n, c)| (n, c.into_bytes())).collect();
    Ok(crate::zip::store(&files))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_and_names() {
        assert_eq!(
            (col(0), col(25), col(26), col(701), col(702)),
            ("A".into(), "Z".into(), "AA".into(), "ZZ".into(), "AAA".into())
        );
        let n = sheet_names(&["BSS".into(), "bss".into(), "a/b:c".into(), " ".into(), "x".repeat(40)]);
        assert_eq!(n[1], "bss (2)");
        assert_eq!(n[2], "a_b_c");
        assert_eq!(n[4].chars().count(), 31);
    }
}
