//! MCS и PHY-скорости 802.11n/ac/ax: что умеет AP по beacon.
//!
//! Перенос `capability()`, `phy_rate()` и `vht_valid()` из `wifi_beacon_scanner/mcs.py`.
//! Скорость - по формуле стандарта: N_SD * N_BPSCS * R * N_SS / T_SYM, порядок операций тот же,
//! что в Python, чтобы совпадали и последние знаки.

use crate::i18n::{tr, trf};
use crate::ie::{map_streams, BssInfo};

/// (бит на поднесущую, кодовая скорость) для MCS 0..13; одинаково для VHT и HE, для HT - MCS по модулю 8.
const MOD: [(u32, f64); 14] = [
    (1, 1.0 / 2.0),
    (2, 1.0 / 2.0),
    (2, 3.0 / 4.0),
    (4, 1.0 / 2.0),
    (4, 3.0 / 4.0),
    (6, 2.0 / 3.0),
    (6, 3.0 / 4.0),
    (6, 5.0 / 6.0),
    (8, 3.0 / 4.0),
    (8, 5.0 / 6.0),
    (10, 3.0 / 4.0),
    (10, 5.0 / 6.0),
    (12, 3.0 / 4.0),
    (12, 5.0 / 6.0),
];

/// Стандарт PHY для расчёта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phy {
    Ht,
    Vht,
    He,
}

impl Phy {
    pub fn as_str(self) -> &'static str {
        match self {
            Phy::Ht => "HT",
            Phy::Vht => "VHT",
            Phy::He => "HE",
        }
    }
    /// Число поднесущих данных по ширине канала.
    fn nsd(self, width: u32) -> Option<u32> {
        match (self, width) {
            (Phy::Ht | Phy::Vht, 20) => Some(52),
            (Phy::Ht | Phy::Vht, 40) => Some(108),
            (Phy::Vht, 80) => Some(234),
            (Phy::Vht, 160) => Some(468),
            (Phy::He, 20) => Some(234),
            (Phy::He, 40) => Some(468),
            (Phy::He, 80) => Some(980),
            (Phy::He, 160) => Some(1960),
            _ => None,
        }
    }
    fn max_mcs(self) -> u32 {
        match self {
            Phy::Ht => 7,
            Phy::Vht => 9,
            Phy::He => 11,
        }
    }
    /// Самый короткий GI, мкс.
    fn shortest_gi(self) -> f64 {
        match self {
            Phy::He => 0.8,
            _ => 0.4,
        }
    }
}

/// В VHT несколько сочетаний MCS/NSS/ширины запрещены стандартом (не делится число бит на символ).
pub fn vht_valid(mcs: u32, nss: u32, width: u32) -> bool {
    !((width == 20 && mcs == 9 && nss != 3 && nss != 6)
        || (width == 80 && ((mcs == 6 && (nss == 3 || nss == 7)) || (mcs == 9 && nss == 6)))
        || (width == 160 && mcs == 9 && nss == 3))
}

/// Скорость в Мбит/с. `mcs` для HT - индекс внутри потока (0..7); `gi` в мкс, по умолчанию самый короткий.
pub fn phy_rate(phy: Phy, mcs: u32, nss: u32, width: u32, gi: Option<f64>) -> Option<f64> {
    let nsd = phy.nsd(width)?;
    if mcs > phy.max_mcs() || nss < 1 {
        return None;
    }
    let gi = gi.unwrap_or_else(|| phy.shortest_gi());
    let tsym = if phy == Phy::He { 12.8 } else { 3.2 } + gi;
    let (bits, r) = MOD[mcs as usize];
    // в Python: nsd * bits * r * nss / tsym - слева направо, nsd * bits целые
    Some(((nsd * bits) as f64 * r * nss as f64) / tsym)
}

fn map_max(m: u16, table: fn(u16) -> u32) -> Option<u32> {
    (0..8).map(|i| (m >> (2 * i)) & 3).filter(|&v| v != 3).map(table).max()
}

fn vht_map_max(v: u16) -> u32 {
    VHT_MAP_MAX[v as usize]
}

fn he_map_max(v: u16) -> u32 {
    HE_MAP_MAX[v as usize]
}

/// Максимум MCS по 2-битному значению карты VHT: 0 -> 7, 1 -> 8, 2 -> 9.
pub const VHT_MAP_MAX: [u32; 3] = [7, 8, 9];
/// Максимум MCS по 2-битному значению карты HE: 0 -> 7, 1 -> 9, 2 -> 11.
pub const HE_MAP_MAX: [u32; 3] = [7, 9, 11];

/// «MCS 0-9, потоков 2», если все потоки одинаковы, иначе по потокам (`map_text` в mcs.py).
pub fn map_text(m: u16, table: &[u32; 3]) -> String {
    let per: Vec<u32> = (0..8)
        .map(|i| (m >> (2 * i)) & 3)
        .filter(|&v| v != 3)
        .map(|v| table[v as usize])
        .collect();
    if per.is_empty() {
        return tr("нет");
    }
    if per.iter().all(|&v| v == per[0]) {
        return trf("MCS 0-%d, потоков %d", &[per[0].into(), per.len().into()]);
    }
    per.iter()
        .enumerate()
        .map(|(i, &v)| trf("поток %d: MCS 0-%d", &[(i + 1).into(), v.into()]))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Битовая маска HT-MCS как диапазоны: «MCS 0-15» (`ht_mask_text` в mcs.py).
pub fn ht_mask_text(mask: u32) -> String {
    let idx: Vec<u32> = (0..32).filter(|i| mask >> i & 1 == 1).collect();
    if idx.is_empty() {
        return tr("нет");
    }
    let mut out = vec![];
    let mut start = idx[0];
    for (k, &a) in idx.iter().enumerate() {
        let next = idx.get(k + 1).copied();
        if next != Some(a + 1) {
            out.push(if start == a {
                a.to_string()
            } else {
                format!("{start}-{a}")
            });
            if let Some(n) = next {
                start = n;
            }
        }
    }
    format!("MCS {}", out.join(", "))
}

/// Что умеет AP по beacon: стандарт, потоки, старший MCS и потолок PHY-скорости на рабочей ширине.
#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    /// "legacy", "HT", "VHT", "HE".
    pub phy: &'static str,
    pub nss: u32,
    pub mcs: Option<u32>,
    pub width: u32,
    pub gi: Option<f64>,
    /// Мбит/с, без округления (в строку таблицы - до 0.1).
    pub rate: Option<f64>,
    /// AP объявляет EHT (Wi-Fi 7) - скорость считается по HE, EHT пока не считаем.
    pub eht_note: bool,
}

fn sgi(info: &BssInfo, width: u32) -> bool {
    match width {
        20 => info.ht_sgi20,
        40 => info.ht_sgi40,
        80 => info.vht_sgi80,
        160 => info.vht_sgi160,
        _ => false,
    }
}

/// Потолок по beacon: теоретический максимум канального уровня при лучшем сигнале и клиенте с тем же
/// числом потоков. Реальная пропускная способность заметно ниже.
pub fn capability(info: &BssInfo) -> Capability {
    let mut width = info.width_mhz();
    let mut out = Capability {
        phy: "legacy",
        nss: 1,
        mcs: None,
        width,
        gi: None,
        rate: None,
        eht_note: info.eht,
    };
    let (phy, nss, mcs, gi) = if let Some(rx80) = info.he_rx80.filter(|&m| info.he && map_streams(m) > 0) {
        let m = match info.he_rx160 {
            Some(m160) if width >= 160 => m160,
            _ => {
                if width >= 160 {
                    width = 80; // карты для 160 нет - считаем по 80
                }
                rx80
            }
        };
        (Phy::He, map_streams(m), map_max(m, he_map_max), 0.8)
    } else if let Some(m) = info.vht_rx_map.filter(|&m| info.vht && map_streams(m) > 0) {
        let nss = map_streams(m);
        let mut mcs = map_max(m, vht_map_max);
        while let Some(x) = mcs.filter(|&x| x > 0 && !vht_valid(x, nss, width)) {
            mcs = Some(x - 1);
        }
        (Phy::Vht, nss, mcs, if sgi(info, width) { 0.4 } else { 0.8 })
    } else if let Some(top) = info.ht_mcs_max.filter(|_| info.ht) {
        width = width.min(40);
        (
            Phy::Ht,
            top / 8 + 1,
            Some(top % 8),
            if sgi(info, width) { 0.4 } else { 0.8 },
        )
    } else {
        out.rate = info
            .rates
            .iter()
            .map(|r| r.0)
            .fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| m.max(x))));
        return out;
    };
    out.phy = phy.as_str();
    out.nss = nss;
    out.mcs = mcs;
    out.width = width;
    out.gi = Some(gi);
    out.rate = mcs.and_then(|m| phy_rate(phy, m, nss, width, Some(gi)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie::round1;

    #[test]
    fn known_rates() {
        // таблицы стандарта: HT MCS 7 x1 20 МГц SGI = 72.2; VHT MCS 9 x2 80 МГц SGI = 866.7; HE MCS 11 x2 80 = 1201
        assert_eq!(round1(phy_rate(Phy::Ht, 7, 1, 20, Some(0.4)).unwrap()), 72.2);
        assert_eq!(round1(phy_rate(Phy::Vht, 9, 2, 80, Some(0.4)).unwrap()), 866.7);
        assert_eq!(round1(phy_rate(Phy::He, 11, 2, 80, Some(0.8)).unwrap()), 1201.0);
        assert_eq!(phy_rate(Phy::Ht, 7, 1, 80, None), None);
    }

    #[test]
    fn vht_forbidden_combinations() {
        assert!(!vht_valid(9, 1, 20));
        assert!(vht_valid(9, 3, 20));
        assert!(!vht_valid(6, 3, 80));
        assert!(!vht_valid(9, 3, 160));
    }
}
