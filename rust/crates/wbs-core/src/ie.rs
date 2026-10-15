//! Разбор Information Elements (IE) из beacon / probe response.
//!
//! Перенос `wifi_beacon_scanner/ie.py` (функция `parse_ies` и `BssInfo`) один в один: те же поля,
//! те же проверки длины, то же поведение на битых данных. Совпадение проверяет `tests/contract.rs`
//! по эталонам `contract/golden`.
//!
//! IE устроен просто: `[id: 1 байт][длина: 1 байт][данные: длина байт]`.
//! Element ID 255 - «расширенный»: первый байт данных - Extension ID.

/// 00-0F-AC: наборы шифров и AKM из стандарта 802.11.
pub const OUI_IEEE: [u8; 3] = [0x00, 0x0f, 0xac];
/// 00-50-F2: Microsoft / WFA (WPA1, WMM, WPS).
pub const OUI_MS: [u8; 3] = [0x00, 0x50, 0xf2];
/// 50-6F-9A: Wi-Fi Alliance (Hotspot 2.0 = тип 0x10).
pub const OUI_WFA: [u8; 3] = [0x50, 0x6f, 0x9a];

/// Extension ID внутри Element ID 255.
pub const EXT_HE_CAP: u8 = 35;
pub const EXT_HE_OP: u8 = 36;
pub const EXT_EHT_OP: u8 = 106;
pub const EXT_EHT_CAP: u8 = 108;

/// Имя набора шифров по типу (OUI 00-0F-AC или 00-50-F2).
pub fn cipher_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "WEP-40",
        2 => "TKIP",
        4 => "CCMP",
        5 => "WEP-104",
        6 => "BIP-CMAC-128",
        8 => "GCMP-128",
        9 => "GCMP-256",
        10 => "CCMP-256",
        _ => return None,
    })
}

/// Имя AKM по типу (OUI 00-0F-AC или 00-50-F2).
pub fn akm_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "802.1X",
        2 => "PSK",
        3 => "FT-802.1X",
        4 => "FT-PSK",
        5 => "802.1X-SHA256",
        6 => "PSK-SHA256",
        8 => "SAE",
        9 => "FT-SAE",
        11 => "Suite-B",
        12 => "Suite-B-192",
        13 => "FT-802.1X-SHA384",
        14 => "FILS-SHA256",
        15 => "FILS-SHA384",
        16 => "FT-FILS-SHA256",
        17 => "FT-FILS-SHA384",
        18 => "OWE",
        23 => "802.1X-SHA384",
        24 => "SAE-EXT-KEY",
        25 => "FT-SAE-EXT-KEY",
        _ => return None,
    })
}

/// BSS membership selector: в Supported Rates он записан как «скорость» с битом basic, но скоростью не является.
pub fn selector_name(v: u8) -> Option<&'static str> {
    Some(match v {
        127 => "HT PHY",
        126 => "VHT PHY",
        125 => "GLK",
        124 => "EPD",
        123 => "SAE H2E only",
        122 => "HE PHY",
        121 => "EHT PHY",
        120 => "UHR PHY",
        _ => return None,
    })
}

/// Байт из Supported Rates - это BSS membership selector, а не скорость.
pub fn is_selector(x: u8) -> bool {
    x & 0x80 != 0 && selector_name(x & 0x7f).is_some()
}

/// Итератор по IE: отдаёт `(id, тело)`. Обрезанный хвост молча отбрасывается (так бывает в реальных кадрах).
pub struct Elements<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let d = self.data;
        if self.pos + 2 > d.len() {
            return None;
        }
        let eid = d[self.pos];
        let len = d[self.pos + 1] as usize;
        let start = self.pos + 2;
        if start + len > d.len() {
            self.pos = d.len(); // хвост обрезан: дальше не идём
            return None;
        }
        self.pos = start + len;
        Some((eid, &d[start..start + len]))
    }
}

pub fn iter_elements(data: &[u8]) -> Elements<'_> {
    Elements { data, pos: 0 }
}

// ---------------------------------------------------------------- RSN / WPA1

/// Содержимое RSN IE (WPA2/WPA3) или WPA1 vendor IE.
#[derive(Debug, Clone, PartialEq)]
pub struct Rsn {
    pub group: String,
    pub pairwise: Vec<String>,
    pub akm: Vec<String>,
    /// PMF: клиент МОЖЕТ использовать (MFPC, бит 7).
    pub mfp_capable: bool,
    /// PMF: клиент ОБЯЗАН использовать (MFPR, бит 6).
    pub mfp_required: bool,
}

impl Default for Rsn {
    fn default() -> Self {
        Rsn {
            group: "CCMP".into(),
            pairwise: vec![],
            akm: vec![],
            mfp_capable: false,
            mfp_required: false,
        }
    }
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn hex_dash(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("-")
}

/// Имя набора (шифр или AKM): для стандартных OUI - по таблице или `type<N>`, для чужих - `aa-bb-cc:<N>`.
fn suite_name(raw: &[u8], table: fn(u8) -> Option<&'static str>) -> String {
    let (oui, typ) = (&raw[..3], raw[3]);
    if oui == OUI_IEEE || oui == OUI_MS {
        table(typ).map(String::from).unwrap_or_else(|| format!("type{typ}"))
    } else {
        format!("{}:{}", hex_dash(oui), typ)
    }
}

/// `b` начинается с поля Version (2 байта). Формат у RSN и WPA1 одинаковый.
/// Обрезанный IE разбирается, сколько есть (как в Python-версии).
pub fn parse_rsn_body(b: &[u8]) -> Option<Rsn> {
    if b.len() < 2 {
        return None;
    }
    let mut rsn = Rsn::default();
    let mut pos = 2;
    if b.len() < pos + 4 {
        return Some(rsn);
    }
    rsn.group = suite_name(&b[pos..pos + 4], cipher_name);
    pos += 4;
    if b.len() < pos + 2 {
        return Some(rsn);
    }
    let cnt = le16(&b[pos..]) as usize;
    pos += 2;
    for _ in 0..cnt {
        if b.len() < pos + 4 {
            return Some(rsn);
        }
        rsn.pairwise.push(suite_name(&b[pos..pos + 4], cipher_name));
        pos += 4;
    }
    if b.len() < pos + 2 {
        return Some(rsn);
    }
    let cnt = le16(&b[pos..]) as usize;
    pos += 2;
    for _ in 0..cnt {
        if b.len() < pos + 4 {
            return Some(rsn);
        }
        rsn.akm.push(suite_name(&b[pos..pos + 4], akm_name));
        pos += 4;
    }
    if b.len() >= pos + 2 {
        let caps = le16(&b[pos..]);
        rsn.mfp_required = caps & 0x40 != 0;
        rsn.mfp_capable = caps & 0x80 != 0;
    }
    Some(rsn)
}

// ---------------------------------------------------------------- BssInfo

/// Vendor IE, которые не разобраны отдельно (всё, кроме WPA1, WMM, WPS).
#[derive(Debug, Clone, PartialEq)]
pub struct VendorIe {
    pub oui: [u8; 3],
    pub typ: u8,
    pub data: Vec<u8>,
}

/// Всё, что извлечено из IE одного BSS. Поля и их смысл - как у `BssInfo` в `ie.py`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BssInfo {
    pub ssid_ie: Option<Vec<u8>>,
    /// (Мбит/с, basic?)
    pub rates: Vec<(f64, bool)>,
    /// BSS membership selectors из тех же IE (127 = HT PHY, 123 = SAE H2E only, ...).
    pub selectors: Vec<u8>,
    pub ds_channel: Option<u8>,
    pub dtim_period: Option<u8>,
    pub country: Option<String>,
    /// QBSS Load (IE 11): станций на BSS.
    pub qbss_stations: Option<u16>,
    /// QBSS Load: занятость канала, %, округлена до 0.1.
    pub qbss_util_pct: Option<f64>,
    pub rsn: Option<Rsn>,
    pub wpa1: Option<Rsn>,
    pub wps: bool,
    pub wmm: bool,
    /// Mobility Domain (IE 54) => 802.11r.
    pub mdid: Option<u16>,
    pub ft_over_ds: bool,
    /// RM Enabled Capabilities (IE 70) => 802.11k.
    pub rm_caps: Option<Vec<u8>>,
    /// Extended Capabilities, бит 19 => 802.11v.
    pub bss_transition: bool,
    pub ext_caps: Vec<u8>,
    /// EDCA Parameter Set (IE 12) => 802.11e.
    pub edca: bool,
    pub power_constraint: Option<u8>,
    pub tpc_tx_power: Option<i8>,
    pub csa: bool,
    pub multi_bssid: bool,
    pub interworking: Option<u8>,
    pub anqp: bool,
    pub roaming_consortium: bool,
    pub mesh_id: Option<Vec<u8>>,
    pub hs20: bool,
    /// HE MAC Capabilities Information (6 байт).
    pub he_mac: Vec<u8>,
    pub ht: bool,
    pub ht_primary: Option<u8>,
    /// 0 - нет, 1 - выше, 3 - ниже.
    pub ht_sec_offset: u8,
    pub ht_width40: bool,
    /// 0 none, 1 nonmember, 2 20MHz, 3 non-HT mixed.
    pub ht_protection: u8,
    pub ht_streams: u32,
    /// Старший HT-MCS из Rx MCS bitmask (0..31).
    pub ht_mcs_max: Option<u32>,
    pub ht_sgi20: bool,
    pub ht_sgi40: bool,
    pub ht_basic_mcs: Option<u32>,
    pub vht: bool,
    /// 0 = 20/40, 1 = 80/160/80+80, устаревшие 2 = 160, 3 = 80+80.
    pub vht_width: Option<u8>,
    pub vht_seg0: u8,
    pub vht_seg1: u8,
    pub vht_streams: u32,
    /// Rx VHT-MCS map: 2 бита на поток, 3 = поток не поддержан.
    pub vht_rx_map: Option<u16>,
    pub vht_tx_map: Option<u16>,
    pub vht_sgi80: bool,
    pub vht_sgi160: bool,
    pub vht_widths: u8,
    pub vht_basic_map: Option<u16>,
    pub he: bool,
    /// HE-MCS map <= 80 МГц: 0 = 0-7, 1 = 0-9, 2 = 0-11, 3 = нет.
    pub he_rx80: Option<u16>,
    pub he_tx80: Option<u16>,
    pub he_rx160: Option<u16>,
    pub he_tx160: Option<u16>,
    pub he_basic_map: Option<u16>,
    pub he_bss_color: Option<u8>,
    pub he_color_disabled: bool,
    /// 6 GHz Operation Information из HE Operation.
    pub he6_primary: Option<u8>,
    /// 0 = 20, 1 = 40, 2 = 80, 3 = 160 (или 80+80).
    pub he6_width: Option<u8>,
    pub he6_ccfs0: u8,
    pub he6_ccfs1: u8,
    pub eht: bool,
    pub vendor_ies: Vec<VendorIe>,
}

/// Номер старшего установленного бита (`None` для нуля).
pub fn top_bit(x: u32) -> Option<u32> {
    if x == 0 {
        None
    } else {
        Some(31 - x.leading_zeros())
    }
}

/// Число потоков в MCS map (VHT/HE): поток считается, если его 2 бита не равны 3.
pub fn map_streams(m: u16) -> u32 {
    (0..8).filter(|i| (m >> (2 * i)) & 3 != 3).count() as u32
}

impl BssInfo {
    /// SAE только с hash-to-element (селектор 123).
    pub fn sae_h2e_only(&self) -> bool {
        self.selectors.contains(&123)
    }

    pub fn dot11k(&self) -> bool {
        self.rm_caps.is_some()
    }

    pub fn neighbor_report(&self) -> bool {
        matches!(&self.rm_caps, Some(c) if !c.is_empty() && c[0] & 0x02 != 0)
    }

    pub fn dot11r(&self) -> bool {
        self.mdid.is_some()
    }

    pub fn dot11v(&self) -> bool {
        self.bss_transition
    }

    /// Бит `n` поля Extended Capabilities (нумерация 802.11: бит 0 - младший бит первого байта).
    pub fn ext_bit(&self, n: usize) -> bool {
        self.ext_caps.len() > n / 8 && (self.ext_caps[n / 8] >> (n % 8)) & 1 == 1
    }

    /// HE MAC Capabilities, бит 2 - TWT Responder; дублируется битом 78 Extended Capabilities.
    pub fn twt_responder(&self) -> bool {
        (!self.he_mac.is_empty() && self.he_mac[0] & 0x04 != 0) || self.ext_bit(78)
    }

    /// Поколение Wi-Fi по наличию IE: 7/6/5/4, 0 - legacy (a/b/g).
    pub fn generation(&self) -> u32 {
        if self.eht {
            7
        } else if self.he {
            6
        } else if self.vht {
            5
        } else if self.ht {
            4
        } else {
            0
        }
    }

    /// Рабочая ширина канала, МГц.
    pub fn width_mhz(&self) -> u32 {
        if let Some(w) = self.he6_width {
            // в 6 ГГц нет HT/VHT Operation, ширина только тут
            return match w {
                0 => 20,
                1 => 40,
                2 => 80,
                3 => 160,
                _ => 20,
            };
        }
        let mut w = 20;
        if self.ht && self.ht_width40 && (self.ht_sec_offset == 1 || self.ht_sec_offset == 3) {
            w = 40;
        }
        match (self.vht, self.vht_width) {
            // seg1 = 0 - 80 МГц; иначе 160 (сегменты в 8 каналах) или 80+80, который для отчёта считаем как 160
            (true, Some(1)) => w = if self.vht_seg1 == 0 { 80 } else { 160 },
            // устаревшая запись (802.11ac-2013): 2 = 160 МГц, 3 = 80+80
            (true, Some(2)) | (true, Some(3)) => w = 160,
            _ => {}
        }
        w
    }

    pub fn he_streams(&self) -> u32 {
        self.he_rx80.map(map_streams).unwrap_or(0)
    }

    pub fn max_streams(&self) -> u32 {
        self.ht_streams.max(self.vht_streams).max(self.he_streams())
    }
}

/// Округление до 0.1 так же, как `round(x, 1)` в Python (по точному двоичному значению, «ничьи» - к чётному).
pub fn round1(x: f64) -> f64 {
    format!("{x:.1}").parse().unwrap_or(x)
}

fn parse_he_cap(info: &mut BssInfo, b: &[u8]) {
    // b[0] = Extension ID; далее HE MAC Capabilities (6), HE PHY Capabilities (11), Supported HE-MCS and NSS Set
    if b.len() < 22 {
        return;
    }
    let phy0 = b[7];
    info.he_rx80 = Some(le16(&b[18..]));
    info.he_tx80 = Some(le16(&b[20..]));
    if phy0 & 0x08 != 0 && b.len() >= 26 {
        // Channel Width Set B2: 160 МГц - есть карты для 160
        info.he_rx160 = Some(le16(&b[22..]));
        info.he_tx160 = Some(le16(&b[24..]));
    }
}

fn parse_he_op(info: &mut BssInfo, b: &[u8]) {
    // b[0] = Extension ID; HE Operation Parameters (3), BSS Color Information (1), Basic HE-MCS and NSS Set (2),
    // затем по флагам: VHT Operation Information (3), Max Co-Hosted BSSID Indicator (1), 6 GHz Operation Information (5)
    if b.len() < 7 {
        return;
    }
    let params = u32::from_le_bytes([b[1], b[2], b[3], 0]);
    info.he_bss_color = Some(b[4] & 0x3f);
    info.he_color_disabled = b[4] & 0x80 != 0;
    info.he_basic_map = Some(le16(&b[5..]));
    let mut off = 7;
    if params & (1 << 14) != 0 {
        off += 3;
    }
    if params & (1 << 15) != 0 {
        off += 1;
    }
    if params & (1 << 17) != 0 && b.len() >= off + 4 {
        info.he6_primary = Some(b[off]);
        info.he6_width = Some(b[off + 1] & 0x03);
        info.he6_ccfs0 = b[off + 2];
        info.he6_ccfs1 = b[off + 3];
    }
}

/// Разбор всех IE одного BSS. Повторный IE того же типа перезаписывает предыдущий (как в Python-версии).
pub fn parse_ies(data: &[u8]) -> BssInfo {
    let mut info = BssInfo::default();
    for (eid, b) in iter_elements(data) {
        match eid {
            0 => info.ssid_ie = Some(b.to_vec()),
            1 | 50 => {
                for &x in b {
                    if is_selector(x) {
                        info.selectors.push(x & 0x7f);
                    } else {
                        info.rates.push(((x & 0x7f) as f64 / 2.0, x & 0x80 != 0));
                    }
                }
            }
            3 if !b.is_empty() => info.ds_channel = Some(b[0]),
            5 if b.len() >= 3 => info.dtim_period = Some(b[1]),
            7 if b.len() >= 2 => {
                // как b[:2].decode("ascii", "replace"): не-ASCII байт -> U+FFFD
                info.country = Some(
                    b[..2]
                        .iter()
                        .map(|&c| if c < 0x80 { c as char } else { '\u{fffd}' })
                        .collect(),
                );
            }
            11 if b.len() >= 3 => {
                info.qbss_stations = Some(le16(b));
                info.qbss_util_pct = Some(round1(b[2] as f64 * 100.0 / 255.0));
            }
            45 if b.len() >= 7 => {
                info.ht = true;
                let flags = le16(b);
                info.ht_sgi20 = flags & 0x20 != 0;
                info.ht_sgi40 = flags & 0x40 != 0;
                for i in 0..4 {
                    // Rx MCS bitmask: по байту на пространственный поток
                    if b[3 + i] != 0 {
                        info.ht_streams = i as u32 + 1;
                    }
                }
                info.ht_mcs_max = top_bit(u32::from_le_bytes([b[3], b[4], b[5], b[6]]));
            }
            61 if b.len() >= 4 => {
                info.ht = true;
                info.ht_primary = Some(b[0]);
                info.ht_sec_offset = b[1] & 0x03;
                info.ht_width40 = b[1] & 0x04 != 0;
                info.ht_protection = b[2] & 0x03;
                if b.len() >= 10 {
                    info.ht_basic_mcs = Some(u32::from_le_bytes([b[6], b[7], b[8], b[9]]));
                }
            }
            48 => info.rsn = parse_rsn_body(b),
            54 if b.len() >= 3 => {
                info.mdid = Some(le16(b));
                info.ft_over_ds = b[2] & 0x01 != 0;
            }
            70 if !b.is_empty() => info.rm_caps = Some(b.to_vec()),
            127 if !b.is_empty() => {
                info.ext_caps = b.to_vec();
                info.bss_transition = b.len() >= 3 && (b[2] >> 3) & 1 == 1; // бит 19
            }
            12 if !b.is_empty() => info.edca = true,
            32 if !b.is_empty() => info.power_constraint = Some(b[0]),
            35 if !b.is_empty() => info.tpc_tx_power = Some(b[0] as i8),
            37 => info.csa = true,
            71 => info.multi_bssid = true,
            107 if !b.is_empty() => info.interworking = Some(b[0]),
            108 => info.anqp = true,
            111 => info.roaming_consortium = true,
            114 => info.mesh_id = Some(b.to_vec()),
            191 if b.len() >= 6 => {
                info.vht = true;
                let caps = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                info.vht_widths = ((caps >> 2) & 3) as u8;
                info.vht_sgi80 = caps & 0x20 != 0;
                info.vht_sgi160 = caps & 0x40 != 0;
                let m = le16(&b[4..]);
                info.vht_rx_map = Some(m);
                info.vht_streams = map_streams(m);
                if b.len() >= 10 {
                    info.vht_tx_map = Some(le16(&b[8..]));
                }
            }
            192 if b.len() >= 3 => {
                info.vht = true;
                info.vht_width = Some(b[0]);
                info.vht_seg0 = b[1];
                info.vht_seg1 = b[2];
                if b.len() >= 5 {
                    info.vht_basic_map = Some(le16(&b[3..]));
                }
            }
            221 if b.len() >= 4 => {
                let oui = [b[0], b[1], b[2]];
                let typ = b[3];
                match (oui, typ) {
                    (OUI_MS, 1) => info.wpa1 = parse_rsn_body(&b[4..]),
                    (OUI_MS, 2) => info.wmm = true,
                    (OUI_MS, 4) => info.wps = true,
                    _ => {
                        if oui == OUI_WFA && typ == 0x10 {
                            info.hs20 = true;
                        }
                        info.vendor_ies.push(VendorIe {
                            oui,
                            typ,
                            data: b[4..].to_vec(),
                        });
                    }
                }
            }
            255 if !b.is_empty() => match b[0] {
                EXT_HE_CAP => {
                    info.he = true;
                    info.he_mac = b[1..b.len().min(7)].to_vec();
                    parse_he_cap(&mut info, b);
                }
                EXT_HE_OP => {
                    info.he = true;
                    parse_he_op(&mut info, b);
                }
                EXT_EHT_CAP | EXT_EHT_OP => info.eht = true,
                _ => {}
            },
            _ => {}
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ie(eid: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![eid, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn truncated_tail_is_dropped() {
        let mut d = ie(3, &[6]);
        d.extend_from_slice(&[221, 10, 1, 2]); // второй IE обрезан
        assert_eq!(iter_elements(&d).collect::<Vec<_>>(), vec![(3u8, &[6u8][..])]);
    }

    #[test]
    fn rsn_wpa3_with_pmf() {
        let body = [
            1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 8, 0xc0, 0,
        ];
        let r = parse_rsn_body(&body).unwrap();
        assert_eq!(r.akm, vec!["SAE"]);
        assert!(r.mfp_capable && r.mfp_required);
    }

    #[test]
    fn unknown_suites() {
        let body = [
            1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0x11, 0x22, 0x33, 5, 1, 0, 0, 0x0f, 0xac, 7,
        ];
        let r = parse_rsn_body(&body).unwrap();
        assert_eq!(r.pairwise, vec!["11-22-33:5"]);
        assert_eq!(r.akm, vec!["type7"]);
    }

    #[test]
    fn selectors_are_not_rates() {
        let i = parse_ies(&ie(1, &[0x8c, 0x12, 0xff, 0xfb]));
        assert_eq!(i.rates, vec![(6.0, true), (9.0, false)]);
        assert_eq!(i.selectors, vec![127, 123]);
        assert!(i.sae_h2e_only());
    }

    #[test]
    fn widths() {
        let ht = ie(61, &[36, 0x05, 0, 0, 0, 0]);
        let w = |vht: &[u8]| parse_ies(&[ht.clone(), ie(192, vht)].concat()).width_mhz();
        assert_eq!(w(&[0, 0, 0]), 40);
        assert_eq!(w(&[1, 42, 0]), 80);
        assert_eq!(w(&[1, 42, 50]), 160);
        assert_eq!(w(&[2, 50, 0]), 160); // устаревшая запись 160
        assert_eq!(w(&[3, 42, 106]), 160); // устаревшая запись 80+80
    }

    #[test]
    fn rounding_like_python() {
        assert_eq!(round1(0.25), 0.2);
        assert_eq!(round1(190.0 * 100.0 / 255.0), 74.5);
        assert_eq!(round1(1733.3333333333333), 1733.3);
    }

    #[test]
    fn tpc_is_signed() {
        assert_eq!(parse_ies(&ie(35, &[0xfe, 0])).tpc_tx_power, Some(-2));
    }
}
