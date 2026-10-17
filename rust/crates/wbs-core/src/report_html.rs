//! HTML-отчёт версии 2 (он же PDF: Edge печатает эту страницу). Те же данные, что в 1.x, но вёрстка своя:
//! шапка с картой каналов (SVG: каждая BSS - своя полоса, высота - сигнал), проблемы по важности, загрузка
//! каналов, подключение ноутбука, сессии, обход, все BSS по сетям. Без скриптов и внешних ресурсов: в HTML
//! действует CSP `default-src 'none'`, отчёт открывается без сети. Печать - A4 альбомом, светлые цвета.
//!
//! Тексты, которые есть в 1.x, идут через каталог (`tr`), новые - через `l(ru, en)`.

use crate::amend::{short, standards};
use crate::clock::iso_naive;
use crate::i18n::{get_lang, pyfmt, tr, Arg, Lang};
use crate::json::Value;
use crate::mcs::capability;
use crate::model::Bss;
use crate::report::{esc, journal_kind_ru, rssi_hue, session_rows, sorted_bss, survey_rows, Cell, ReportInput};
use crate::rules::{CRITICAL, INFO, WARNING};

/// Текст на языке отчёта для строк, которых нет в 1.x.
fn l(ru: &str, en: &str) -> String {
    match get_lang() {
        Lang::Ru => ru.to_string(),
        Lang::En => en.to_string(),
    }
}

const CSS: &str = r#"
:root{--paper:#fff;--ink:#15202b;--mut:#5b6875;--rule:#dce3e9;--soft:#f3f6f8;--accent:#0a6c8f;--accent-soft:#e3f1f6;
--crit:#b4261f;--crit-soft:#fbeceb;--warn:#a15c00;--warn-soft:#fbf1e1;--info:#2c5fa8;--info-soft:#e9effa;--good:#1e7b45;
--other:#7c8a97;--mono:"Cascadia Mono",Consolas,"DejaVu Sans Mono",monospace}
@media (prefers-color-scheme:dark){:root{--paper:#11161b;--ink:#e3e8ed;--mut:#93a0ad;--rule:#26313b;--soft:#18202a;
--accent:#56c1e6;--accent-soft:#16303c;--crit:#ff8b80;--crit-soft:#3a1f1d;--warn:#f1b35b;--warn-soft:#382a16;
--info:#8db4f5;--info-soft:#1c2840;--good:#6fd296;--other:#7b8794}}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
font-variant-numeric:tabular-nums}
main{max-width:1280px;margin:0 auto;padding:32px 28px 48px}
a{color:var(--accent)}
.mono{font-family:var(--mono);font-size:12.5px}
.mut{color:var(--mut)}
h1{font:600 30px/1.15 "Segoe UI Variable Display","Segoe UI",system-ui,sans-serif;margin:6px 0 18px;letter-spacing:-.01em}
h2{font-size:19px;line-height:1.3;margin:0 0 4px}
.brand{display:flex;align-items:center;gap:8px;color:var(--accent);font-weight:600;font-size:14px}
.brand svg{width:22px;height:22px}
.head{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 40px;align-items:end;border-bottom:2px solid var(--ink);padding-bottom:18px}
.meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:3px 14px;margin:0;font-size:13px}
.meta dt{color:var(--mut)}.meta dd{margin:0}
.verdict{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}
.sev{min-width:118px;padding:8px 14px 9px;border-radius:6px;border:1px solid transparent}
.sev b{display:block;font-size:28px;line-height:1.1}.sev span{font-size:13px}
.sev.critical{background:var(--crit-soft);color:var(--crit)}.sev.warning{background:var(--warn-soft);color:var(--warn)}
.sev.info{background:var(--info-soft);color:var(--info)}.sev.zero{background:none;border-color:var(--rule);color:var(--mut)}
.facts{display:flex;flex-wrap:wrap;gap:6px 34px;margin:18px 0 6px;font-size:13px;color:var(--mut)}
.facts b{display:block;color:var(--ink);font-size:20px;font-weight:600}
.map{margin:18px 0 8px}
.band{margin:0 0 10px}
.band figcaption{display:flex;gap:10px;align-items:baseline;font-weight:600;font-size:13px;margin-bottom:2px}
.band figcaption span{font-weight:400;color:var(--mut)}
.band svg{display:block;width:100%;height:auto;overflow:visible}
.band text{font-family:"Segoe UI",system-ui,sans-serif;fill:var(--mut);font-size:10px}
.band .lbl{fill:var(--ink);font-size:10.5px}
.band .grid{stroke:var(--rule);stroke-width:1}
.band .grid.dash{stroke-dasharray:3 4}
.band .base{stroke:var(--mut);stroke-width:1}
.band .dfs{fill:var(--soft)}
.band .mine{fill:var(--accent);fill-opacity:.2;stroke:var(--accent);stroke-width:1.3}
.band .other{fill:var(--other);fill-opacity:.12;stroke:var(--other);stroke-width:1;stroke-dasharray:3 2}
.legend{display:flex;gap:18px;flex-wrap:wrap;font-size:12.5px;color:var(--mut);margin:2px 0 0}
.legend i{display:inline-block;width:16px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.legend .mine{background:var(--accent-soft);border:1.3px solid var(--accent)}
.legend .other{border:1px dashed var(--other)}
.legend .dfs{background:var(--soft);border:1px solid var(--rule)}
nav.toc{display:flex;flex-wrap:wrap;gap:6px 22px;margin:22px 0 0;padding:10px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);font-size:13px}
nav.toc a{text-decoration:none}nav.toc span{color:var(--mut)}
section{margin-top:38px}
.lead{margin:0 0 14px;color:var(--mut);max-width:78ch}
.f{display:grid;grid-template-columns:150px minmax(0,1.3fr) minmax(0,1fr);gap:4px 24px;padding:12px 0;border-top:1px solid var(--rule)}
.f:last-child{border-bottom:1px solid var(--rule)}
.f .what{font-weight:600;font-size:13px}
.f.critical .what{color:var(--crit)}.f.warning .what{color:var(--warn)}.f.info .what{color:var(--info)}
.f .code{display:block;font-family:var(--mono);font-size:11px;color:var(--mut);font-weight:400}
.f h3{margin:0 0 2px;font-size:15px}
.f p{margin:0}
.f .check{font-size:13.5px}.f .check b{display:block;font-size:12.5px;color:var(--mut);font-weight:600}
.f .aff{margin-top:6px;font-family:var(--mono);font-size:11.5px;color:var(--mut);overflow-wrap:anywhere}
.ok{padding:14px 16px;border-radius:6px;background:var(--soft)}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{font-size:12px;font-weight:600;color:var(--mut);text-align:left;padding:6px 10px 6px 0;border-bottom:1.5px solid var(--ink);white-space:nowrap}
td{padding:5px 10px 5px 0;border-bottom:1px solid var(--rule);vertical-align:top}
td.n,th.n{text-align:right}
td.nw{white-space:nowrap}
td.why{min-width:220px}
tr.grp th{padding:16px 0 5px;border-bottom:1px solid var(--rule);color:var(--ink);font-size:14px}
tr.grp th small{font-weight:400;color:var(--mut);font-size:12px;margin-left:8px}
tr.grp.mine th{color:var(--accent)}
.bar{display:inline-block;width:110px;height:8px;border-radius:4px;background:var(--soft);overflow:hidden;vertical-align:1px;margin-right:8px}
.bar i{display:block;height:100%;border-radius:4px}
.sig{display:inline-block;width:38px;height:6px;border-radius:3px;background:var(--soft);overflow:hidden;vertical-align:2px;margin-left:6px}
.sig i{display:block;height:100%}
.tag{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;background:var(--soft);white-space:nowrap}
.tag.critical{background:var(--crit-soft);color:var(--crit)}.tag.warning{background:var(--warn-soft);color:var(--warn)}
.tag.good{color:var(--good)}
.kpis{display:flex;flex-wrap:wrap;gap:6px 34px;margin:0 0 14px;font-size:13px;color:var(--mut)}
.kpis b{display:block;font-size:20px;color:var(--ink);font-weight:600}
.kpis .bad b{color:var(--crit)}
footer{margin-top:44px;padding-top:12px;border-top:1px solid var(--rule);font-size:12px;color:var(--mut);display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}
@page{size:A4 landscape;margin:11mm 12mm}
@media print{
:root{--paper:#fff;--ink:#15202b;--mut:#5b6875;--rule:#dce3e9;--soft:#f3f6f8;--accent:#0a6c8f;--accent-soft:#e3f1f6;
--crit:#b4261f;--crit-soft:#fbeceb;--warn:#a15c00;--warn-soft:#fbf1e1;--info:#2c5fa8;--info-soft:#e9effa;--good:#1e7b45;--other:#7c8a97}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font-size:10.5px}main{max-width:none;padding:0}
h1{font-size:24px}h2{font-size:15px;break-after:avoid}
nav.toc{display:none}
section{margin-top:22px}
.f,tr,.band{break-inside:avoid}
.f{grid-template-columns:120px minmax(0,1.3fr) minmax(0,1fr)}
table{font-size:9.5px}th{font-size:9px}.mono{font-size:9.5px}
.tw{overflow:visible}
}
"#;

const LOGO: &str = "<svg viewBox='0 0 24 24' aria-hidden='true'><path d='M2.5 9.2a14 14 0 0 1 19 0M5.6 12.6a9.4 9.4 0 0 1 12.8 0M8.7 16a4.9 4.9 0 0 1 6.6 0' fill='none' stroke='currentColor' stroke-width='2.1' stroke-linecap='round'/><circle cx='12' cy='19.4' r='1.6' fill='currentColor'/></svg>";

fn vf(v: Option<&Value>) -> f64 {
    v.and_then(Value::as_f64).unwrap_or(0.0)
}
fn vi(v: Option<&Value>) -> i64 {
    v.and_then(Value::as_f64).map_or(0, |x| x as i64)
}
fn vs(v: Option<&Value>) -> String {
    match v {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Int(n)) => n.to_string(),
        Some(Value::Num(x)) => crate::i18n::py_float(*x),
        _ => String::new(),
    }
}

fn sig_color(rssi: f64) -> String {
    format!("hsl({} 70% 38%)", rssi_hue(rssi))
}

fn util_color(u: f64) -> String {
    let hue = (130.0 * (1.0 - (u / 75.0).clamp(0.0, 1.0))).round() as i64;
    format!("hsl({hue} 65% 42%)")
}

/// «2026-10-17T22:49:54+03:00» -> «17 октября 2026, 22:49».
pub fn human_time(iso: &str) -> String {
    let p = |a: usize, b: usize| iso.get(a..b).and_then(|s| s.parse::<usize>().ok());
    let (Some(y), Some(m), Some(d), Some(hh), Some(mm)) = (p(0, 4), p(5, 7), p(8, 10), p(11, 13), p(14, 16)) else {
        return iso.to_string();
    };
    if !(1..=12).contains(&m) {
        return iso.to_string();
    }
    const RU: [&str; 12] = [
        "января",
        "февраля",
        "марта",
        "апреля",
        "мая",
        "июня",
        "июля",
        "августа",
        "сентября",
        "октября",
        "ноября",
        "декабря",
    ];
    const EN: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    match get_lang() {
        Lang::Ru => format!("{d} {} {y}, {hh:02}:{mm:02}", RU[m - 1]),
        Lang::En => format!("{d} {} {y}, {hh:02}:{mm:02}", EN[m - 1]),
    }
}

/// Русское окончание по числу: 1 проблема, 2 проблемы, 5 проблем.
fn plural(n: usize, one: &str, few: &str, many: &str) -> String {
    let (m10, m100) = (n % 10, n % 100);
    let w = if m10 == 1 && m100 != 11 {
        one
    } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
        few
    } else {
        many
    };
    format!("{n} {w}")
}

fn is_mine(b: &Bss, focus: &[String]) -> bool {
    !focus.is_empty() && focus.iter().any(|f| *f == b.ssid())
}

// ---------------------------------------------------------------- карта каналов

/// Частота центра занятой полосы, МГц.
fn center_mhz(b: &Bss) -> f64 {
    let cc = b.center_channel();
    match b.band() {
        "2.4" if b.channel() == 14 => 2484.0,
        "2.4" => 2407.0 + 5.0 * cc,
        "5" => 5000.0 + 5.0 * cc,
        _ => 5950.0 + 5.0 * cc,
    }
}

fn chan_mhz(band: &str, ch: i32) -> f64 {
    match band {
        "2.4" if ch == 14 => 2484.0,
        "2.4" => 2407.0 + 5.0 * ch as f64,
        "5" => 5000.0 + 5.0 * ch as f64,
        _ => 5950.0 + 5.0 * ch as f64,
    }
}

const MAP_W: f64 = 1000.0;
const X0: f64 = 34.0;
const X1: f64 = 994.0;
const Y_TOP: f64 = 8.0;
const Y_BASE: f64 = 108.0;
const RSSI_TOP: f64 = -30.0;
const RSSI_BOTTOM: f64 = -95.0;

fn y_of(rssi: f64) -> f64 {
    let r = rssi.clamp(RSSI_BOTTOM, RSSI_TOP);
    Y_BASE - (r - RSSI_BOTTOM) / (RSSI_TOP - RSSI_BOTTOM) * (Y_BASE - Y_TOP)
}

/// Одна полоса карты: BSS диапазона как трапеции по занятой полосе, высота - RSSI.
fn band_svg(band: &str, bss: &[&Bss], focus: &[String]) -> String {
    let (mut lo, mut hi) = match band {
        "2.4" => (2401.0, 2484.0 + 11.0),
        "5" => (5170.0, 5835.0),
        _ => (5945.0, 7125.0),
    };
    for b in bss {
        let (c, w) = (center_mhz(b), b.info.width_mhz().max(20) as f64);
        lo = f64::min(lo, c - w / 2.0);
        hi = f64::max(hi, c + w / 2.0);
    }
    let x = |f: f64| X0 + (f - lo) / (hi - lo) * (X1 - X0);
    let mut s = format!(
        "<svg viewBox='0 0 {MAP_W} 128' role='img' aria-label='{}'>",
        esc(&format!("{} {} GHz", l("Карта каналов", "Channel map"), band))
    );
    if band == "5" {
        // DFS: каналы 52-144
        let (a, b) = (x(5250.0), x(5730.0));
        s += &format!(
            "<rect class='dfs' x='{a:.1}' y='{Y_TOP}' width='{:.1}' height='{:.1}'/><text x='{:.1}' y='{:.1}'>DFS</text>",
            b - a,
            Y_BASE - Y_TOP,
            a + 4.0,
            Y_TOP + 11.0
        );
    }
    for r in [-50.0, -70.0, -90.0] {
        let y = y_of(r);
        s += &format!(
            "<line class='grid dash' x1='{X0}' x2='{X1}' y1='{y:.1}' y2='{y:.1}'/><text x='{:.1}' y='{:.1}' text-anchor='end'>{r:.0}</text>",
            X0 - 6.0,
            y + 3.5
        );
    }
    s += &format!("<line class='base' x1='{X0}' x2='{X1}' y1='{Y_BASE}' y2='{Y_BASE}'/>");
    // подписи каналов: основные границы диапазона и каналы, на которых есть BSS
    let base_ticks: Vec<i32> = match band {
        "2.4" => (1..=13).collect(),
        "5" => vec![36, 52, 100, 116, 132, 149, 165],
        _ => vec![1, 33, 65, 97, 129, 161, 193, 225],
    };
    let mut used: Vec<i32> = bss.iter().map(|b| b.channel()).collect();
    used.sort_unstable();
    used.dedup();
    let mut placed_x: Vec<f64> = vec![];
    for ch in used.iter().chain(base_ticks.iter()).copied() {
        let tx = x(chan_mhz(band, ch));
        if !(X0 - 1.0..=X1 + 1.0).contains(&tx) || placed_x.iter().any(|p| (p - tx).abs() < 18.0) {
            continue;
        }
        placed_x.push(tx);
        let strong = used.contains(&ch);
        s += &format!(
            "<line class='grid' x1='{tx:.1}' x2='{tx:.1}' y1='{Y_BASE}' y2='{:.1}'/><text x='{tx:.1}' y='124' text-anchor='middle'{}>{ch}</text>",
            Y_BASE + 4.0,
            if strong { " class='lbl'" } else { "" }
        );
    }
    // сильные - сзади, слабые - поверх; свои - поверх чужих
    let mut order: Vec<&&Bss> = bss.iter().collect();
    order.sort_by_key(|b| (is_mine(b, focus), -b.rssi));
    for b in &order {
        let (c, w) = (center_mhz(b), b.info.width_mhz().max(20) as f64);
        let (xa, xb) = (x(c - w / 2.0), x(c + w / 2.0));
        let slope = ((xb - xa) * 0.12).min(9.0);
        let yt = y_of(b.rssi as f64);
        let cls = if focus.is_empty() || is_mine(b, focus) {
            "mine"
        } else {
            "other"
        };
        s += &format!(
            "<polygon class='{cls}' points='{xa:.1},{Y_BASE} {:.1},{yt:.1} {:.1},{yt:.1} {xb:.1},{Y_BASE}'><title>{}</title></polygon>",
            xa + slope,
            xb - slope,
            esc(&format!(
                "{} {} · {} {}, {} MHz · {} dBm",
                b.ssid_display(),
                b.bssid,
                l("канал", "channel"),
                b.channel(),
                b.info.width_mhz(),
                b.rssi
            ))
        );
    }
    // подписи сетей: самая сильная BSS сети на канале; без наложений
    let mut cand: Vec<&&Bss> = bss.iter().collect();
    cand.sort_by_key(|b| -b.rssi);
    let mut placed: Vec<(f64, f64, f64)> = vec![];
    let mut seen: Vec<(String, i32)> = vec![];
    for b in cand {
        let key = (b.ssid_display(), b.channel());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let name = b.ssid_display();
        let wpx = name.chars().count() as f64 * 5.8 + 6.0;
        let cx = x(center_mhz(b));
        let y = y_of(b.rssi as f64) - 4.0;
        let (a, z) = (cx - wpx / 2.0, cx + wpx / 2.0);
        if y < Y_TOP + 2.0
            || placed
                .iter()
                .any(|&(pa, pz, py)| a < pz && z > pa && (py - y).abs() < 12.0)
        {
            continue;
        }
        placed.push((a, z, y));
        s += &format!(
            "<text class='lbl' x='{cx:.1}' y='{y:.1}' text-anchor='middle'>{}</text>",
            esc(&name)
        );
    }
    s + "</svg>"
}

fn channel_map(r: &ReportInput) -> String {
    let mut out = String::from("<div class='map'>");
    for (band, name) in [("2.4", "2,4"), ("5", "5"), ("6", "6")] {
        let bss: Vec<&Bss> = r.snap.bss.iter().filter(|b| b.band() == band).collect();
        if bss.is_empty() {
            continue;
        }
        let ghz = match get_lang() {
            Lang::Ru => format!("{name} ГГц"),
            Lang::En => format!("{} GHz", name.replace(',', ".")),
        };
        out += &format!(
            "<figure class='band'><figcaption>{ghz}<span>{}</span></figcaption>{}</figure>",
            match get_lang() {
                Lang::Ru => plural(bss.len(), "BSS", "BSS", "BSS"),
                Lang::En => format!("{} BSS", bss.len()),
            },
            band_svg(band, &bss, r.focus)
        );
    }
    out += &format!(
        "<div class='legend'><span><i class='mine'></i>{}</span><span><i class='other'></i>{}</span><span><i class='dfs'></i>{}</span><span>{}</span></div></div>",
        if r.focus.is_empty() {
            l("сети", "networks")
        } else {
            l("мои SSID", "my SSIDs")
        },
        l("соседи", "neighbours"),
        l("DFS (5 ГГц, каналы 52–144)", "DFS (5 GHz, channels 52–144)"),
        l(
            "Ширина фигуры - занятая полоса, высота - сигнал, дБм",
            "Shape width is the occupied bandwidth, height is the signal, dBm"
        )
    );
    out
}

// ---------------------------------------------------------------- разделы

fn sev_name(s: &str) -> String {
    tr(match s {
        CRITICAL => "Критично",
        WARNING => "Внимание",
        _ => "Информация",
    })
}

fn findings(r: &ReportInput) -> String {
    let mut out = format!(
        "<section id='problems'><h2>{}</h2><p class='lead'>{}</p>",
        tr("Проблемы"),
        l(
            "Сначала критичные. Справа - что проверить; внизу каждой - затронутые BSS.",
            "Critical first. On the right: what to check; below each one: the affected BSSs."
        )
    );
    if r.findings.is_empty() {
        out += &format!(
            "<p class='ok'>{}</p>",
            esc(&l(
                "Проблем по заданным правилам не найдено.",
                "No problems found by the configured rules."
            ))
        );
    }
    out += "<div>";
    for sev in [CRITICAL, WARNING, INFO] {
        for f in r.findings.iter().filter(|f| f.severity == sev) {
            let aff = if f.bssids.is_empty() {
                String::new()
            } else {
                let shown: Vec<&str> = f.bssids.iter().take(10).map(String::as_str).collect();
                let more = if f.bssids.len() > 10 {
                    format!(" +{}", f.bssids.len() - 10)
                } else {
                    String::new()
                };
                format!("<div class='aff'>{}{more}</div>", esc(&shown.join("  ")))
            };
            let check = if f.recommendation.is_empty() {
                String::new()
            } else {
                format!(
                    "<b>{}</b>{}",
                    esc(&l("Что проверить", "What to check")),
                    esc(&f.recommendation)
                )
            };
            out += &format!(
                "<article class='f {sev}'><div class='what'>{}<span class='code'>{}</span></div><div><h3>{}</h3><p>{}</p>{aff}</div><div class='check'>{check}</div></article>",
                sev_name(sev),
                esc(&f.code),
                esc(&f.title),
                esc(&f.detail)
            );
        }
    }
    out + "</div></section>"
}

fn load(r: &ReportInput) -> String {
    let Some(util) = r.util else { return String::new() };
    let channels = util
        .get("channels")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if channels.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "<section id='load'><h2>{}</h2><p class='lead'>{}</p><div class='tw'><table><thead><tr><th>{}</th><th class='n'>{}</th><th>{}</th><th>{}</th><th class='n'>{}</th><th class='n'>{}</th><th class='n'>{}</th><th>{}</th></tr></thead><tbody>",
        l("Загрузка каналов (QBSS Load)", "Channel load (QBSS Load)"),
        esc(&l("Доля времени, когда сама AP считает канал занятым; на канал взят максимум среди AP, сообщающих эту цифру.", "Share of time the AP itself considers the channel busy; per channel the maximum among APs that report it.")),
        tr("ГГц"),
        tr("Канал"),
        tr("Загрузка"),
        tr("Уровень"),
        l("Среднее", "Average"),
        tr("AP с данными"),
        tr("Станций"),
        tr("Самые загруженные")
    );
    for ch in &channels {
        let aps = ch.get("aps").and_then(Value::as_array).cloned().unwrap_or_default();
        let top = aps
            .iter()
            .take(3)
            .map(|a| pyfmt("%s %.0f%%", &[Arg::S(vs(a.get("ssid"))), Arg::F(vf(a.get("util")))]))
            .collect::<Vec<_>>()
            .join(", ");
        let mx = vf(ch.get("max"));
        out += &format!(
            "<tr><td>{}</td><td class='n'>{}</td><td class='nw'><span class='bar'><i style='width:{:.0}%;background:{}'></i></span>{:.0}%</td><td>{}</td><td class='n'>{:.0}%</td><td class='n'>{} / {}</td><td class='n'>{}</td><td>{}</td></tr>",
            esc(&vs(ch.get("band"))),
            vs(ch.get("channel")),
            mx.max(1.0),
            util_color(mx),
            mx,
            esc(&vs(ch.get("label"))),
            vf(ch.get("avg")),
            vi(ch.get("reporting")),
            vi(ch.get("bss")),
            vi(ch.get("stations")),
            esc(&top)
        );
    }
    out += "</tbody></table></div>";
    let no_data = util
        .get("no_data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !no_data.is_empty() {
        let list = no_data
            .iter()
            .map(|x| {
                crate::i18n::trf(
                    "%s ГГц канал %s",
                    &[Arg::S(vs(x.get("band"))), Arg::S(vs(x.get("channel")))],
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        out += &format!(
            "<p class='mut'>{}</p>",
            esc(&(l("Нет данных QBSS Load: ", "No QBSS Load data: ") + &list + "."))
        );
    }
    out + "</section>"
}

fn connection(r: &ReportInput) -> String {
    let Some(j) = r.journal.filter(|j| !j.events.is_empty()) else {
        return String::new();
    };
    let st = j.stats();
    let kpi = |n: i64, label: &str, bad: bool| {
        format!(
            "<div{}><b>{n}</b>{}</div>",
            if bad && n > 0 { " class='bad'" } else { "" },
            esc(label)
        )
    };
    let mut out = format!(
        "<section id='connection'><h2>{}</h2><p class='lead'>{}</p><div class='kpis'>{}{}{}{}{}<div><b>{:.0} {}</b>{}</div></div>",
        l("Подключение ноутбука", "Laptop connection"),
        l(
            "Что происходило с подключением ноутбука, на котором снят отчёт: роуминги, обрывы, пинг-понг и залипание на слабой точке. Новые события сверху.",
            "What happened to the connection of the laptop that made this report: roams, drops, ping-pong and sticking to a weak AP. Newest first."
        ),
        kpi(vi(st.get("roams")), &l("Роумингов", "Roams"), false),
        kpi(vi(st.get("disconnects")), &tr("Обрывов"), true),
        kpi(vi(st.get("pingpong")), &tr("Пинг-понгов"), true),
        kpi(vi(st.get("sticky")), &tr("Залипаний"), true),
        kpi(vi(st.get("attempt_fail")), &l("Неудачных подключений", "Failed connections"), true),
        vf(st.get("down_s")),
        l("с", "s"),
        l("без связи", "without connection")
    );
    out += &format!(
        "<div class='tw'><table><thead><tr><th>{}</th><th>{}</th><th>SSID</th><th>{}</th><th>{}</th><th>RSSI</th><th class='n'>{}</th><th>{}</th></tr></thead><tbody>",
        tr("Время"),
        tr("Событие"),
        tr("Откуда"),
        tr("Куда"),
        l("Длительность", "Duration"),
        tr("Причина")
    );
    let skip = j.events.len().saturating_sub(200);
    for ev in j.events.iter().skip(skip).rev() {
        let rs = [ev.rssi_from, ev.rssi_to]
            .iter()
            .flatten()
            .map(|x| format!("<b style='color:{}'>{x}</b>", sig_color(*x as f64)))
            .collect::<Vec<_>>()
            .join(" → ");
        let dur = ev
            .duration_s
            .map(|d| pyfmt("%.0f", &[Arg::F(d)]) + " " + &l("с", "s"))
            .unwrap_or_default();
        let kind = match journal_kind_ru(&ev.kind) {
            Some(k) => tr(k),
            None => ev.kind.clone(),
        };
        let cls = match ev.severity.as_str() {
            "critical" => " critical",
            "warning" => " warning",
            _ => "",
        };
        out += &format!(
            "<tr><td class='nw'>{}</td><td><span class='tag{cls}'>{}</span></td><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td><td class='nw'>{rs}</td><td class='n nw'>{dur}</td><td>{}</td></tr>",
            &iso_naive(ev.t, r.offset_min)[11..19],
            esc(&kind),
            esc(&ev.ssid),
            esc(&ev.bssid_from),
            esc(&ev.bssid_to),
            esc(&ev.reason)
        );
    }
    out + "</tbody></table></div></section>"
}

fn sessions(r: &ReportInput) -> String {
    let Some(j) = r.journal.filter(|j| !j.sessions.sessions.is_empty()) else {
        return String::new();
    };
    let skip = j.sessions.sessions.len().saturating_sub(200);
    let ss: Vec<&crate::session::Session> = j.sessions.sessions.iter().skip(skip).rev().collect();
    let rows = session_rows(&ss, r.offset_min);
    // время, тип, итог, SSID, откуда, куда, ассоциация, аутентификация, всего, до IPv4, EAP, 802.1X, причина
    const KEEP: [usize; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 15, 16];
    const NUM: [usize; 4] = [6, 7, 8, 9];
    let mut out = format!(
        "<section id='sessions'><h2>{}</h2><p class='lead'>{}</p><div class='tw'><table><thead><tr>{}</tr></thead><tbody>",
        l("Сессии подключения", "Connection sessions"),
        esc(&l("Стадии по уведомлениям Windows: ассоциация, аутентификация (802.1X и 4-way handshake), получение IPv4.", "Stages from Windows notifications: association, authentication (802.1X and 4-way handshake), getting IPv4.")),
        KEEP.iter()
            .map(|&i| format!(
                "<th{}>{}</th>",
                if NUM.contains(&i) { " class='n'" } else { "" },
                esc(&rows[0][i].text())
            ))
            .collect::<String>()
    );
    for (row, s) in rows[1..].iter().zip(&ss) {
        let mut tds = String::new();
        for &i in &KEEP {
            let t = esc(&row[i].text());
            tds += &match i {
                0 => format!("<td class='nw'>{t}</td>"),
                2 => {
                    let cls = match s.result.as_str() {
                        "ok" => " good",
                        "fail" => " critical",
                        _ => "",
                    };
                    format!("<td><span class='tag{cls}'>{t}</span></td>")
                }
                4 | 5 => format!("<td class='mono nw'>{t}</td>"),
                13 | 15 | 1 => format!("<td class='nw'>{t}</td>"),
                16 => format!("<td class='why'>{t}</td>"),
                _ if NUM.contains(&i) => format!("<td class='n'>{t}</td>"),
                _ => format!("<td>{t}</td>"),
            };
        }
        out += &format!("<tr>{tds}</tr>");
    }
    out + "</tbody></table></div></section>"
}

fn survey(r: &ReportInput) -> String {
    if r.survey.is_empty() {
        return String::new();
    }
    let rows = survey_rows(r.survey, r.focus, r.offset_min);
    let rcols: Vec<bool> = rows[0].iter().map(|h| h.text().contains("RSSI")).collect();
    let mut out = format!(
        "<section id='survey'><h2>{}</h2><p class='lead'>{}</p><div class='tw'><table><thead><tr>{}</tr></thead><tbody>",
        l("Обход: точки замеров", "Survey: measurement points"),
        esc(&l("Карта покрытия сохраняется отдельно из вкладки «Обход» (PNG).", "The coverage map is saved separately from the Survey tab (PNG).")),
        rows[0]
            .iter()
            .map(|h| format!("<th>{}</th>", esc(&h.text())))
            .collect::<String>()
    );
    for row in &rows[1..] {
        out += "<tr>";
        for (i, v) in row.iter().enumerate() {
            out += &match (rcols[i], v) {
                (true, Cell::Int(n)) => format!("<td><b style='color:{}'>{n}</b></td>", sig_color(*n as f64)),
                _ => format!("<td>{}</td>", esc(&v.text())),
            };
        }
        out += "</tr>";
    }
    out + "</tbody></table></div></section>"
}

fn all_bss(r: &ReportInput) -> String {
    let heads = [
        ("BSSID", ""),
        ("Вендор", ""),
        ("ГГц", ""),
        ("Канал", "n"),
        ("Ширина", "n"),
        ("RSSI", ""),
        ("Безопасность", ""),
        ("Поколение", ""),
        ("Макс. MCS", ""),
        ("Макс. PHY, Мбит/с", "n"),
        ("802.11", ""),
        ("Загрузка", "n"),
        ("Станций", "n"),
        ("Страна", ""),
    ];
    let mut out =
        format!(
        "<section id='bss'><h2>{}</h2><p class='lead'>{}</p><div class='tw'><table><thead><tr>{}</tr></thead><tbody>",
        l("Все BSS", "All BSSs"),
        l(
            "По сетям; мои SSID - первыми. Внутри сети - по диапазону, каналу и сигналу.",
            "By network, my SSIDs first. Within a network: by band, channel and signal."
        ),
        heads
            .iter()
            .map(|(h, c)| format!(
                "<th{}>{}</th>",
                if c.is_empty() { String::new() } else { format!(" class='{c}'") },
                esc(&tr(h))
            ))
            .collect::<String>()
    );
    let sorted = sorted_bss(&r.snap.bss);
    let mut groups: Vec<(String, Vec<&Bss>)> = vec![];
    for b in sorted {
        let name = b.ssid_display();
        match groups.last_mut() {
            Some((n, v)) if *n == name => v.push(b),
            _ => groups.push((name, vec![b])),
        }
    }
    // стабильная сортировка: мои SSID первыми, скрытые - последними, иначе прежний порядок
    groups.sort_by_key(|(_, v)| (!is_mine(v[0], r.focus), v[0].hidden()));
    for (name, list) in &groups {
        let mine = is_mine(list[0], r.focus);
        out += &format!(
            "<tr class='grp{}'><th colspan='{}'>{}<small>{}{}</small></th></tr>",
            if mine { " mine" } else { "" },
            heads.len(),
            esc(name),
            list.len(),
            if mine {
                format!(" BSS, {}", l("мой SSID", "my SSID"))
            } else {
                " BSS".into()
            }
        );
        for b in list {
            let i = &b.info;
            let cap = capability(i);
            let mcs = cap
                .mcs
                .map_or(String::new(), |m| format!("{} {} ×{}", cap.phy, m, cap.nss));
            let rate = cap.rate.map_or(String::new(), |x| pyfmt("%.0f", &[Arg::F(x)]));
            let util = i.qbss_util_pct.map_or(String::new(), |u| pyfmt("%.0f%%", &[Arg::F(u)]));
            let w = ((b.rssi as f64 - RSSI_BOTTOM) / (RSSI_TOP - RSSI_BOTTOM) * 100.0).clamp(4.0, 100.0);
            out += &format!(
                "<tr><td class='mono nw'>{}</td><td class='nw'>{}</td><td>{}</td><td class='n'>{}</td><td class='n'>{}</td><td class='nw'><b style='color:{c}'>{}</b><span class='sig'><i style='width:{w:.0}%;background:{c}'></i></span></td><td class='nw'>{}</td><td class='nw'>{}</td><td class='nw'>{}</td><td class='n'>{}</td><td class='mono nw'>{}</td><td class='n'>{}</td><td class='n'>{}</td><td>{}</td></tr>",
                esc(&b.bssid),
                esc(b.vendor.as_deref().unwrap_or("")),
                b.band(),
                b.channel(),
                i.width_mhz(),
                b.rssi,
                esc(&b.security()),
                esc(&b.generation_label()),
                esc(&mcs),
                rate,
                esc(&short(&standards(b))),
                util,
                i.qbss_stations.map(|x| x.to_string()).unwrap_or_default(),
                esc(i.country.as_deref().unwrap_or("")),
                c = sig_color(b.rssi as f64),
            );
        }
    }
    out + "</tbody></table></div></section>"
}

/// HTML-отчёт целиком.
pub fn render_html(r: &ReportInput) -> String {
    let snap = r.snap;
    let lang = get_lang().code();
    let count = |sev: &str| r.findings.iter().filter(|f| f.severity == sev).count();
    let title = l("Отчёт о радиообстановке", "Wi-Fi survey report");
    let mut out = format!(
        "<!doctype html><html lang='{lang}'><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\"><meta name='viewport' content='width=device-width,initial-scale=1'><title>Wi-Fi Beacon Scanner: {}</title><style>{CSS}</style></head><body><main>",
        esc(&title)
    );
    // шапка: что, когда, чем; справа - итог по проблемам
    let iface = if snap.interface.is_empty() {
        "-"
    } else {
        &snap.interface
    };
    let mut meta = format!(
        "<dt>{}</dt><dd>{}</dd><dt>{}</dt><dd>{}</dd>",
        l("Снято", "Captured"),
        esc(&human_time(&snap.taken_at)),
        l("Адаптер", "Adapter"),
        esc(iface)
    );
    if !r.focus.is_empty() {
        meta += &format!(
            "<dt>{}</dt><dd>{}</dd>",
            l("Мои SSID", "My SSIDs"),
            esc(&r.focus.join(", "))
        );
    }
    if !r.note.is_empty() {
        meta += &format!("<dt>{}</dt><dd>{}</dd>", l("В отчёте", "Included"), esc(r.note));
    }
    let sev = |n: usize, cls: &str, ru: (&str, &str, &str), en: (&str, &str)| {
        let label = match get_lang() {
            Lang::Ru => plural(n, ru.0, ru.1, ru.2)
                .split_once(' ')
                .map(|(_, w)| w.to_string())
                .unwrap_or_default(),
            Lang::En => (if n == 1 { en.0 } else { en.1 }).to_string(),
        };
        format!(
            "<div class='sev {}'><b>{n}</b><span>{}</span></div>",
            if n == 0 { "zero" } else { cls },
            esc(&label)
        )
    };
    out += &format!(
        "<header><div class='brand'>{LOGO}Wi-Fi Beacon Scanner</div><div class='head'><div><h1>{}</h1><dl class='meta'>{meta}</dl></div><div class='verdict'>{}{}{}</div></div>",
        esc(&title),
        sev(count(CRITICAL), CRITICAL, ("критичная", "критичных", "критичных"), ("critical", "critical")),
        sev(count(WARNING), WARNING, ("предупреждение", "предупреждения", "предупреждений"), ("warning", "warnings")),
        sev(count(INFO), INFO, ("замечание", "замечания", "замечаний"), ("note", "notes")),
    );
    // факты об эфире
    let band_n = |band: &str| snap.bss.iter().filter(|b| b.band() == band).count();
    let ssids = {
        let mut v: Vec<String> = snap
            .bss
            .iter()
            .filter(|b| !b.hidden())
            .map(|b| b.ssid_display())
            .collect();
        v.sort();
        v.dedup();
        v.len()
    };
    let pool: Vec<&Bss> = if r.focus.is_empty() {
        snap.bss.iter().collect()
    } else {
        snap.bss.iter().filter(|b| is_mine(b, r.focus)).collect()
    };
    let best = pool.iter().max_by_key(|b| b.rssi);
    let busiest = r
        .util
        .and_then(|u| u.get("channels"))
        .and_then(Value::as_array)
        .and_then(|a| a.first().cloned());
    let mut facts = format!(
        "<div><b>{}</b>BSS</div><div><b>{ssids}</b>SSID</div><div><b>{} / {} / {}</b>{}</div>",
        snap.bss.len(),
        band_n("2.4"),
        band_n("5"),
        band_n("6"),
        l("2,4 / 5 / 6 ГГц", "2.4 / 5 / 6 GHz")
    );
    if let Some(b) = best {
        facts += &format!(
            "<div><b style='color:{}'>{} {}</b>{}</div>",
            sig_color(b.rssi as f64),
            b.rssi,
            l("дБм", "dBm"),
            esc(&format!("{}, {}", l("лучший сигнал", "best signal"), b.ssid_display()))
        );
    }
    if let Some(ch) = busiest {
        facts += &format!(
            "<div><b>{:.0}%</b>{}</div>",
            vf(ch.get("max")),
            esc(&format!(
                "{} {} {}",
                l("загрузка, канал", "load, channel"),
                vs(ch.get("channel")),
                match get_lang() {
                    Lang::Ru => format!("({} ГГц)", vs(ch.get("band"))),
                    Lang::En => format!("({} GHz)", vs(ch.get("band"))),
                }
            ))
        );
    }
    out += &format!("<div class='facts'>{facts}</div>");
    out += &channel_map(r);
    // оглавление: только разделы, которые есть
    let body_parts = [
        ("problems", tr("Проблемы"), findings(r)),
        ("load", l("Загрузка каналов", "Channel load"), load(r)),
        (
            "connection",
            l("Подключение ноутбука", "Laptop connection"),
            connection(r),
        ),
        ("sessions", l("Сессии подключения", "Connection sessions"), sessions(r)),
        ("survey", l("Обход", "Survey"), survey(r)),
        ("bss", l("Все BSS", "All BSSs"), all_bss(r)),
    ];
    out += &format!(
        "<nav class='toc'><span>{}</span>{}</nav></header>",
        l("Разделы:", "Sections:"),
        body_parts
            .iter()
            .filter(|p| !p.2.is_empty())
            .map(|(id, name, _)| format!("<a href='#{id}'>{}</a>", esc(name)))
            .collect::<String>()
    );
    for (_, _, html) in &body_parts {
        out += html;
    }
    out += &format!(
        "<footer><span>Wi-Fi Beacon Scanner {}</span><span>{}</span></footer></main></body></html>",
        esc(r.version),
        l(
            "Данные - из beacon и probe response, которые видит адаптер ноутбука; это не monitor mode.",
            "Data comes from the beacons and probe responses the laptop's adapter sees; this is not monitor mode."
        )
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_and_plural() {
        crate::i18n::with_lang(Lang::Ru, || {
            assert_eq!(human_time("2026-10-17T22:49:54+03:00"), "17 октября 2026, 22:49");
            assert_eq!(plural(1, "a", "b", "c"), "1 a");
            assert_eq!(plural(3, "a", "b", "c"), "3 b");
            assert_eq!(plural(11, "a", "b", "c"), "11 c");
            assert_eq!(plural(22, "a", "b", "c"), "22 b");
        });
        crate::i18n::with_lang(Lang::En, || {
            assert_eq!(human_time("2026-01-05T07:03:00Z"), "5 January 2026, 07:03")
        });
        assert_eq!(human_time("bad"), "bad");
    }
}
