//! Дерево IE для вкладки «Beacon»: имя, длина, краткое описание, поля, hex.
//!
//! Перенос `_decode()` и `describe_ies()` из `wifi_beacon_scanner/ie.py` ветка в ветку: те же условия
//! на длину, те же тексты (через каталог переводов), тот же порядок полей.

use crate::i18n::{tr, trf, Arg};
use crate::ie::{is_selector, iter_elements, parse_rsn_body, selector_name, top_bit, EXT_HE_CAP, EXT_HE_OP, OUI_MS};
use crate::json::Value;
use crate::mcs::{ht_mask_text, map_text, HE_MAP_MAX, VHT_MAP_MAX};

/// Один IE во вкладке Beacon.
#[derive(Debug, Clone, PartialEq)]
pub struct IeNode {
    pub id: u8,
    pub name: String,
    pub len: usize,
    pub summary: String,
    pub fields: Vec<(String, String)>,
    pub hex: String,
}

impl IeNode {
    pub fn to_value(&self) -> Value {
        Value::Obj(vec![
            ("id".into(), self.id.into()),
            ("name".into(), self.name.as_str().into()),
            ("len".into(), self.len.into()),
            ("summary".into(), self.summary.as_str().into()),
            (
                "fields".into(),
                Value::Arr(
                    self.fields
                        .iter()
                        .map(|(k, v)| Value::Arr(vec![k.as_str().into(), v.as_str().into()]))
                        .collect(),
                ),
            ),
            ("hex".into(), self.hex.as_str().into()),
        ])
    }
}

fn ie_name(eid: u8) -> Option<&'static str> {
    Some(match eid {
        0 => "SSID",
        1 => "Supported Rates",
        3 => "DS Parameter Set",
        5 => "TIM",
        7 => "Country",
        11 => "QBSS Load",
        45 => "HT Capabilities",
        48 => "RSN",
        50 => "Extended Supported Rates",
        54 => "Mobility Domain (802.11r)",
        61 => "HT Operation",
        70 => "RM Enabled Capabilities (802.11k)",
        127 => "Extended Capabilities",
        191 => "VHT Capabilities",
        192 => "VHT Operation",
        12 => "EDCA Parameter Set (802.11e)",
        32 => "Power Constraint (802.11h)",
        35 => "TPC Report (802.11h)",
        37 => "Channel Switch Announcement (802.11h)",
        71 => "Multiple BSSID",
        107 => "Interworking (802.11u)",
        108 => "Advertisement Protocol (802.11u)",
        111 => "Roaming Consortium (802.11u)",
        114 => "Mesh ID (802.11s)",
        221 => "Vendor Specific",
        255 => "Extension",
        _ => return None,
    })
}

fn ext_name(id: u8) -> Option<&'static str> {
    Some(match id {
        35 => "HE Capabilities",
        36 => "HE Operation",
        106 => "EHT Operation (ID сверить с 802.11be)",
        108 => "EHT Capabilities (ID сверить с 802.11be)",
        _ => return None,
    })
}

/// Тип сети в Interworking (802.11u), по-русски - ключ перевода.
pub fn access_network_type(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "частная сеть",
        1 => "частная с гостевым доступом",
        2 => "платная публичная",
        3 => "бесплатная публичная",
        4 => "личное устройство",
        5 => "только экстренные службы",
        14 => "тестовая",
        15 => "любая (wildcard)",
        _ => return None,
    })
}

/// Биты Extended Capabilities (IEEE 802.11-2020, Table 9-153), которые показываем по имени.
pub const EXT_CAP_BITS: &[(usize, &str)] = &[
    (0, "20/40 BSS Coexistence Management"),
    (2, "Extended Channel Switching"),
    (11, "FMS (802.11v)"),
    (12, "Proxy ARP (802.11v)"),
    (14, "Civic Location"),
    (15, "Geospatial Location"),
    (16, "TFS (802.11v)"),
    (17, "WNM Sleep Mode (802.11v)"),
    (18, "TIM Broadcast (802.11v)"),
    (19, "BSS Transition (802.11v)"),
    (22, "Multiple BSSID"),
    (23, "Timing Measurement"),
    (26, "DMS (802.11v)"),
    (31, "Interworking (802.11u)"),
    (32, "QoS Map (802.11u)"),
    (46, "WNM Notification (802.11v)"),
    (48, "UTF-8 SSID"),
    (62, "Operating Mode Notification"),
    (70, "FTM Responder (802.11mc)"),
    (71, "FTM Initiator (802.11mc)"),
    (72, "FILS (802.11ai)"),
    (77, "TWT Requester"),
    (78, "TWT Responder"),
];

fn yn(v: bool) -> String {
    tr(if v { "да" } else { "нет" })
}

fn hex_sp(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

fn hex_dash(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("-")
}

/// Первые `n` символов строки (как срез `[:n]` в Python).
fn first(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// %g для скорости k/2: «5.5», «54».
fn rate_g(x: f64) -> String {
    crate::i18n::py_g(x)
}

/// round(x, 1) и str() как в Python: «74.5», «0.0».
fn pct(u8v: u8) -> String {
    crate::i18n::py_float(crate::ie::round1(u8v as f64 * 100.0 / 255.0))
}

type Fields = Vec<(String, String)>;

fn f(k: impl Into<String>, v: impl ToString) -> (String, String) {
    (k.into(), v.to_string())
}

fn decode(eid: u8, b: &[u8]) -> (String, Fields) {
    match eid {
        0 => {
            let t = String::from_utf8_lossy(b).into_owned();
            let t = if t.is_empty() { tr("<скрыт>") } else { t };
            (t.clone(), vec![f("SSID", t)])
        }
        1 | 50 => {
            let rates: Vec<u8> = b.iter().copied().filter(|&x| !is_selector(x)).collect();
            let sels: Vec<&str> = b
                .iter()
                .filter(|&&x| is_selector(x))
                .filter_map(|&x| selector_name(x & 0x7f))
                .collect();
            let s = if rates.is_empty() {
                "—".to_string()
            } else {
                rates
                    .iter()
                    .map(|&x| {
                        format!(
                            "{}{}",
                            rate_g((x & 0x7f) as f64 / 2.0),
                            if x & 0x80 != 0 { "*" } else { "" }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
                    + &tr(" Мбит/с")
            };
            let mut fl = vec![f(tr("Скорости (* = basic)"), &s)];
            if !sels.is_empty() {
                fl.push(f("BSS membership selectors", sels.join(", ")));
                let head = if rates.is_empty() {
                    String::new()
                } else {
                    format!("{s}; ")
                };
                return (head + &tr("требуется: ") + &sels.join(", "), fl);
            }
            (s, fl)
        }
        3 if !b.is_empty() => (trf("канал %d", &[b[0].into()]), vec![f(tr("Канал"), b[0])]),
        5 if b.len() >= 2 => (
            format!("DTIM period {}", b[1]),
            vec![f("DTIM count", b[0]), f("DTIM period", b[1])],
        ),
        7 if b.len() >= 2 => {
            let cc: String = b[..2]
                .iter()
                .map(|&c| if c < 0x80 { c as char } else { '\u{fffd}' })
                .collect();
            (cc.clone(), vec![f(tr("Код страны"), cc)])
        }
        11 if b.len() >= 3 => {
            let st = le16(b);
            let u = pct(b[2]);
            let mut fl = vec![f(tr("Станций"), st), f(tr("Загрузка канала"), format!("{u}%"))];
            if b.len() >= 5 {
                fl.push(f("Admission capacity", le16(&b[3..])));
            }
            (trf("станций %d, загрузка %s%%", &[st.into(), u.into()]), fl)
        }
        45 if b.len() >= 3 => {
            let flags = le16(b);
            let mut streams = 0u32;
            for i in 0..4 {
                if 3 + i < b.len() && b[3 + i] != 0 {
                    streams = i as u32 + 1;
                }
            }
            let mut fl = vec![
                f("HT Capability Info", format!("0x{flags:04X}")),
                f(tr("Ширина 40 МГц"), yn(flags & 0x02 != 0)),
                f(tr("Short GI 20 МГц"), yn(flags & 0x20 != 0)),
                f(tr("Short GI 40 МГц"), yn(flags & 0x40 != 0)),
                f(tr("Пространственных потоков (Rx)"), streams),
            ];
            if b.len() >= 19 {
                let mask = u32::from_le_bytes([b[3], b[4], b[5], b[6]]);
                fl.push(f("Rx MCS (bitmask)", ht_mask_text(mask)));
                let hi = le16(&b[13..]) & 0x3ff;
                if hi != 0 {
                    fl.push(f("Rx Highest Supported Data Rate", trf("%d Мбит/с", &[hi.into()])));
                }
                let tx = b[15];
                let txs = if tx & 1 != 0 && tx & 2 == 0 {
                    tr("как Rx")
                } else if tx & 1 != 0 {
                    tr("задан отдельно")
                } else {
                    tr("не указан")
                };
                fl.push(f("Tx MCS Set", txs));
                let top: Arg = match top_bit(mask) {
                    Some(t) => t.into(),
                    None => "-".into(),
                };
                return (trf("потоков %d, до MCS %s", &[streams.into(), top]), fl);
            }
            (trf("потоков %d", &[streams.into()]), fl)
        }
        48 => match parse_rsn_body(b) {
            None => (String::new(), vec![f(tr("Данные"), hex_sp(b))]),
            Some(r) => {
                let akm = if r.akm.is_empty() {
                    "—".to_string()
                } else {
                    r.akm.join(", ")
                };
                let pw = if r.pairwise.is_empty() {
                    "—".to_string()
                } else {
                    r.pairwise.join(", ")
                };
                (
                    format!("{akm}; {pw}"),
                    vec![
                        f(tr("Групповой шифр"), &r.group),
                        f("Pairwise", &pw),
                        f("AKM", &akm),
                        f("PMF capable (MFPC)", yn(r.mfp_capable)),
                        f("PMF required (MFPR)", yn(r.mfp_required)),
                    ],
                )
            }
        },
        54 if b.len() >= 3 => {
            let m = le16(b);
            (
                format!("MDID 0x{m:04X}"),
                vec![f("MDID", format!("0x{m:04X}")), f("FT over DS", yn(b[2] & 1 != 0))],
            )
        }
        61 if b.len() >= 3 => {
            let width = tr(if b[1] & 4 != 0 { "40 МГц" } else { "20 МГц" });
            let sec = match b[1] & 3 {
                0 => tr("нет"),
                1 => tr("выше"),
                3 => tr("ниже"),
                _ => tr("?"),
            };
            let prot = ["none", "non-member", "20 MHz", "non-HT mixed"][(b[2] & 3) as usize];
            let mut fl = vec![
                f(tr("Основной канал"), b[0]),
                f(tr("Вторичный канал"), sec),
                f(tr("Ширина"), &width),
                f("HT protection", prot),
            ];
            if b.len() >= 10 {
                fl.push(f(
                    tr("Basic MCS Set (обязательные)"),
                    ht_mask_text(u32::from_le_bytes([b[6], b[7], b[8], b[9]])),
                ));
            }
            (trf("основной %d, %s", &[b[0].into(), width.into()]), fl)
        }
        70 if !b.is_empty() => (
            format!("neighbor report {}", yn(b[0] & 2 != 0)),
            vec![
                f("Neighbor report", yn(b[0] & 2 != 0)),
                f(tr("Сырой байт"), format!("0x{:02X}", b[0])),
            ],
        ),
        127 if !b.is_empty() => {
            let on: Vec<&(usize, &str)> = EXT_CAP_BITS
                .iter()
                .filter(|(n, _)| b.len() > n / 8 && (b[n / 8] >> (n % 8)) & 1 == 1)
                .collect();
            let mut fl: Fields = on
                .iter()
                .map(|(n, name)| f(trf("Бит %d", &[(*n).into()]), name))
                .collect();
            fl.push(f(tr("Длина поля"), trf("%d байт", &[b.len().into()])));
            let bt = b.len() >= 3 && (b[2] >> 3) & 1 == 1;
            let rest = on.len() - bt as usize;
            let tail = if on.len() > bt as usize {
                trf("; ещё %d", &[rest.into()])
            } else {
                String::new()
            };
            (format!("BSS Transition: {}{tail}", yn(bt)), fl)
        }
        32 if !b.is_empty() => (
            trf("%d дБ", &[b[0].into()]),
            vec![f(
                tr("Снижение мощности относительно лимита страны"),
                trf("%d дБ", &[b[0].into()]),
            )],
        ),
        35 if !b.is_empty() => {
            let tx = b[0] as i8;
            let mut fl = vec![f(tr("Мощность передачи"), trf("%d дБм", &[tx.into()]))];
            if b.len() >= 2 {
                fl.push(f("Link margin", trf("%d дБ", &[b[1].into()])));
            }
            (trf("TX %d дБм", &[tx.into()]), fl)
        }
        37 if b.len() >= 3 => (
            trf("на канал %d через %d beacon", &[b[1].into(), b[2].into()]),
            vec![
                f(
                    tr("Режим"),
                    tr(if b[0] != 0 {
                        "передача запрещена до переключения"
                    } else {
                        "передача разрешена"
                    }),
                ),
                f(tr("Новый канал"), b[1]),
                f(tr("Через beacon"), b[2]),
            ],
        ),
        107 if !b.is_empty() => {
            let t = b[0] & 0x0f;
            let ant = tr(&access_network_type(t)
                .map(String::from)
                .unwrap_or_else(|| t.to_string()));
            let fl = vec![
                f(tr("Тип сети"), &ant),
                f(tr("Доступ в интернет"), yn(b[0] & 0x10 != 0)),
                f(tr("ASRA (нужно доп. действие)"), yn(b[0] & 0x20 != 0)),
                f(tr("Экстренные службы (ESR)"), yn(b[0] & 0x40 != 0)),
                f("UESA", yn(b[0] & 0x80 != 0)),
            ];
            let s = if b[0] & 0x10 != 0 {
                ant.clone() + &tr(", интернет")
            } else {
                ant.clone()
            };
            (s, fl)
        }
        114 => {
            let t = String::from_utf8_lossy(b).into_owned();
            (
                if t.is_empty() { tr("(пусто)") } else { t.clone() },
                vec![f("Mesh ID", t)],
            )
        }
        191 if b.len() >= 6 => {
            let caps = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let mm = le16(&b[4..]);
            let vals: Vec<(usize, u16)> = (0..8)
                .map(|i| (i, (mm >> (2 * i)) & 3))
                .filter(|&(_, v)| v != 3)
                .collect();
            let parts: Vec<String> = vals
                .iter()
                .map(|&(i, v)| format!("{}:{}", i + 1, ["MCS 0-7", "MCS 0-8", "MCS 0-9"][v as usize]))
                .collect();
            let widths = match (caps >> 2) & 3 {
                0 => tr("нет (до 80 МГц)"),
                1 => tr("160 МГц"),
                2 => tr("160 и 80+80 МГц"),
                _ => tr("?"),
            };
            let mut fl = vec![
                f("Rx VHT-MCS", map_text(mm, &VHT_MAP_MAX)),
                f(
                    tr("Rx VHT-MCS по потокам"),
                    if parts.is_empty() {
                        tr("нет")
                    } else {
                        parts.join(" / ")
                    },
                ),
                f(tr("Пространственных потоков"), parts.len()),
                f(tr("Ширины сверх 80 МГц"), widths),
                f(tr("Short GI 80 МГц"), yn(caps & 0x20 != 0)),
                f(tr("Short GI 160 МГц"), yn(caps & 0x40 != 0)),
                f("SU beamformer", yn(caps & (1 << 11) != 0)),
                f("MU beamformer", yn(caps & (1 << 19) != 0)),
            ];
            if b.len() >= 10 {
                fl.insert(1, f("Tx VHT-MCS", map_text(le16(&b[8..]), &VHT_MAP_MAX)));
            }
            let mx = vals.iter().map(|&(_, v)| VHT_MAP_MAX[v as usize]).max().unwrap_or(0);
            (trf("потоков %d, до MCS %d", &[parts.len().into(), mx.into()]), fl)
        }
        192 if b.len() >= 3 => {
            let w = match b[0] {
                0 => tr("20/40 МГц"),
                1 => tr("80/160/80+80 МГц"),
                2 => tr("160 МГц"),
                3 => tr("80+80 МГц"),
                _ => tr("?"),
            };
            let mut fl = vec![
                f(tr("Ширина"), &w),
                f(tr("Центр сегмента 0"), b[1]),
                f(tr("Центр сегмента 1"), b[2]),
            ];
            if b.len() >= 5 {
                fl.push(f(
                    tr("Basic VHT-MCS and NSS (обязательные)"),
                    map_text(le16(&b[3..]), &VHT_MAP_MAX),
                ));
            }
            (tr("ширина ") + &w, fl)
        }
        221 if b.len() >= 4 => {
            let (oui, typ) = (&b[..3], b[3]);
            if oui == OUI_MS {
                let name = match typ {
                    1 => "WPA (WPA1)".to_string(),
                    2 => "WMM".to_string(),
                    4 => "WPS".to_string(),
                    t => format!("Microsoft type {t}"),
                };
                let mut fl = vec![
                    f("OUI", "00-50-F2 (Microsoft)"),
                    f(tr("Тип"), format!("{typ} ({name})")),
                ];
                if typ == 1 {
                    if let Some(r) = parse_rsn_body(&b[4..]) {
                        fl.push(f(
                            "AKM",
                            if r.akm.is_empty() {
                                "—".into()
                            } else {
                                r.akm.join(", ")
                            },
                        ));
                        fl.push(f(
                            tr("Шифры"),
                            if r.pairwise.is_empty() {
                                "—".into()
                            } else {
                                r.pairwise.join(", ")
                            },
                        ));
                    }
                }
                return (name, fl);
            }
            let ascii: String = b[4..]
                .iter()
                .map(|&x| if (32..127).contains(&x) { x as char } else { '.' })
                .collect();
            (
                trf("OUI %s, тип %d", &[hex_dash(oui).into(), typ.into()]),
                vec![
                    f("OUI", hex_dash(oui)),
                    f(tr("Тип"), typ),
                    f("ASCII", ascii),
                    f("Hex", first(&hex_sp(&b[4..]), 120)),
                ],
            )
        }
        255 if !b.is_empty() => {
            if b[0] == EXT_HE_CAP && b.len() >= 22 {
                return decode_he_cap(b);
            }
            if b[0] == EXT_HE_OP && b.len() >= 7 {
                return decode_he_op(b);
            }
            let name = ext_name(b[0]).map(tr).filter(|s| !s.is_empty());
            let name = name.unwrap_or_else(|| trf("расширение %d", &[b[0].into()]));
            (name, vec![f("Extension ID", b[0]), f(tr("Длина"), b.len())])
        }
        _ => (String::new(), vec![f(tr("Данные"), first(&hex_sp(b), 120))]),
    }
}

fn decode_he_cap(b: &[u8]) -> (String, Fields) {
    let phy0 = b[7];
    let rx80 = le16(&b[18..]);
    let mut fl = vec![
        f("Extension ID", "35 (HE Capabilities)"),
        f(tr("Rx HE-MCS, до 80 МГц"), map_text(rx80, &HE_MAP_MAX)),
        f(tr("Tx HE-MCS, до 80 МГц"), map_text(le16(&b[20..]), &HE_MAP_MAX)),
        f(tr("40 МГц в 2.4 ГГц"), yn(phy0 & 0x02 != 0)),
        f(tr("40/80 МГц в 5/6 ГГц"), yn(phy0 & 0x04 != 0)),
        f(tr("160 МГц"), yn(phy0 & 0x08 != 0)),
        f(tr("80+80 МГц"), yn(phy0 & 0x10 != 0)),
    ];
    if phy0 & 0x08 != 0 && b.len() >= 26 {
        fl.push(f(tr("Rx HE-MCS, 160 МГц"), map_text(le16(&b[22..]), &HE_MAP_MAX)));
        fl.push(f(tr("Tx HE-MCS, 160 МГц"), map_text(le16(&b[24..]), &HE_MAP_MAX)));
    }
    let per: Vec<u32> = (0..8)
        .map(|i| (rx80 >> (2 * i)) & 3)
        .filter(|&v| v != 3)
        .map(|v| HE_MAP_MAX[v as usize])
        .collect();
    let summary = match per.iter().max() {
        Some(&mx) => trf("потоков %d, до MCS %d", &[per.len().into(), mx.into()]),
        None => "HE Capabilities".into(),
    };
    (summary, fl)
}

fn decode_he_op(b: &[u8]) -> (String, Fields) {
    let params = u32::from_le_bytes([b[1], b[2], b[3], 0]);
    let color = b[4] & 0x3f;
    let mut fl = vec![
        f("Extension ID", "36 (HE Operation)"),
        f(
            "BSS Color",
            format!(
                "{color}{}",
                if b[4] & 0x80 != 0 {
                    tr(" (отключён)")
                } else {
                    String::new()
                }
            ),
        ),
        f(
            tr("Basic HE-MCS and NSS (обязательные)"),
            map_text(le16(&b[5..]), &HE_MAP_MAX),
        ),
        f("TWT required", yn(params & 0x08 != 0)),
        f(tr("ER SU отключён"), yn(params & (1 << 16) != 0)),
    ];
    let off = 7 + if params & (1 << 14) != 0 { 3 } else { 0 } + if params & (1 << 15) != 0 { 1 } else { 0 };
    let mut summary = format!("BSS Color {color}");
    if params & (1 << 17) != 0 && b.len() >= off + 4 {
        let w: u32 = [20, 40, 80, 160][(b[off + 1] & 3) as usize];
        fl.push(f(tr("6 ГГц: основной канал"), b[off]));
        fl.push(f(tr("6 ГГц: ширина"), trf("%d МГц", &[w.into()])));
        fl.push(f(tr("6 ГГц: CCFS0"), b[off + 2]));
        fl.push(f(tr("6 ГГц: CCFS1"), b[off + 3]));
        if b.len() >= off + 5 {
            fl.push(f(
                tr("6 ГГц: минимальная скорость"),
                trf("%d Мбит/с", &[b[off + 4].into()]),
            ));
        }
        summary += &trf(", 6 ГГц канал %d, %d МГц", &[b[off].into(), w.into()]);
    }
    (summary, fl)
}

/// Список IE в виде, удобном для показа (вкладка Beacon).
pub fn describe_ies(data: &[u8]) -> Vec<IeNode> {
    iter_elements(data)
        .map(|(eid, body)| {
            let (summary, fields) = decode(eid, body);
            let name = if eid == 255 && !body.is_empty() {
                let n = ext_name(body[0])
                    .map(String::from)
                    .unwrap_or_else(|| format!("ID {}", body[0]));
                format!("Extension: {}", tr(&n))
            } else {
                tr(&ie_name(eid)
                    .map(String::from)
                    .unwrap_or_else(|| format!("Element {eid}")))
            };
            IeNode {
                id: eid,
                name,
                len: body.len(),
                summary,
                fields,
                hex: hex_sp(body),
            }
        })
        .collect()
}
