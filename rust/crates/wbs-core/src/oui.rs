//! Вендор по BSSID из файла `manuf` (Wireshark). Перенос `wifi_beacon_scanner/oui.py`.
//!
//! Строки файла:
//! ```text
//! 00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc          (блок /24)
//! 70:B3:D5:FF:F0:00/36<TAB>Short<TAB>Long name       (блок /36, /28 и т.д.)
//! ```
//! Ищется самое длинное совпадение префикса; имя - длинное, если есть, иначе короткое.

use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct OuiDb {
    /// длина префикса в битах -> {значение префикса: имя}
    by_bits: Vec<(u32, HashMap<u64, String>)>,
}

impl OuiDb {
    pub fn parse(text: &str) -> OuiDb {
        let mut map: HashMap<u32, HashMap<u64, String>> = HashMap::new();
        for line in text.lines() {
            let line = line.trim_start_matches('\u{feff}');
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.trim_end_matches('\r').split('\t').collect();
            if cols.len() < 2 {
                continue;
            }
            let name = if cols.len() > 2 && !cols[2].trim().is_empty() {
                cols[2].trim()
            } else {
                cols[1].trim()
            };
            let (prefix, bits) = match cols[0].trim().split_once('/') {
                Some((p, b)) => match b.parse::<u32>() {
                    Ok(b) => (p, b),
                    Err(_) => continue,
                },
                None => (cols[0].trim(), 24),
            };
            let hex: String = prefix.chars().filter(|c| *c != ':' && *c != '-').collect();
            if hex.is_empty() || !hex.len().is_multiple_of(2) || hex.len() > 16 {
                continue;
            }
            let Ok(mut val) = u64::from_str_radix(&hex, 16) else {
                continue;
            };
            let total = hex.len() as u32 * 4;
            if total < bits || bits == 0 || bits > 48 {
                continue;
            }
            val >>= total - bits;
            map.entry(bits).or_default().insert(val, name.to_string());
        }
        let mut by_bits: Vec<(u32, HashMap<u64, String>)> = map.into_iter().collect();
        by_bits.sort_by_key(|e| std::cmp::Reverse(e.0));
        OuiDb { by_bits }
    }

    pub fn len(&self) -> usize {
        self.by_bits.iter().map(|(_, m)| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn lookup(&self, bssid: &str) -> Option<&str> {
        let hex: String = bssid.chars().filter(|c| *c != ':' && *c != '-').collect();
        let raw = u64::from_str_radix(&hex, 16).ok()?;
        for (bits, m) in &self.by_bits {
            if let Some(name) = m.get(&(raw >> (48 - bits))) {
                return Some(name);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix() {
        let db = OuiDb::parse(
            "# comment\n00:00:0C\tCisco\tCisco Systems, Inc\n70:B3:D5\tIEEE\n70:B3:D5:FF:F0:00/36\tShort\tLong name\nAC:DE:48\tPriv\n",
        );
        assert_eq!(db.len(), 4);
        assert_eq!(db.lookup("00:00:0c:12:34:56"), Some("Cisco Systems, Inc"));
        assert_eq!(db.lookup("70:b3:d5:ff:f0:12"), Some("Long name"));
        assert_eq!(db.lookup("70:b3:d5:00:00:01"), Some("IEEE"));
        assert_eq!(db.lookup("02:00:00:00:00:01"), None);
    }
}
