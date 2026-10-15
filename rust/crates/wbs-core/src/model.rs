//! Модель одного BSS (одна точка доступа на одном радио) и снапшот скана.
//!
//! Перенос `wifi_beacon_scanner/model.py`: диапазон и канал по частоте, центр полосы, защита, шифры, поколение.

use crate::ie::{parse_ies, BssInfo};
use crate::json::{self, Value};

/// Версия формата снапшота (поле `version` в JSON «Экспорт → JSON»).
pub const SNAPSHOT_VERSION: i64 = 1;

/// Диапазон по частоте центра канала (кГц, как отдаёт Windows).
pub fn freq_to_band(freq_khz: u32) -> &'static str {
    if freq_khz < 3_000_000 {
        "2.4"
    } else if freq_khz < 5_925_000 {
        "5"
    } else {
        "6"
    }
}

/// Номер канала по частоте. Деление - с округлением вниз, как `//` в Python.
pub fn freq_to_channel(freq_khz: u32) -> i32 {
    if freq_khz == 2_484_000 {
        return 14;
    }
    if freq_khz == 5_935_000 {
        return 2; // 6 ГГц, канал 2: вне сетки 5950 + 5·n
    }
    let base: i64 = match freq_to_band(freq_khz) {
        "2.4" => 2_407_000,
        "5" => 5_000_000,
        _ => 5_950_000,
    };
    (freq_khz as i64 - base).div_euclid(5000) as i32
}

/// Один BSS из скана: поля из WLAN_BSS_ENTRY и разобранные IE.
#[derive(Debug, Clone, PartialEq)]
pub struct Bss {
    /// "aa:bb:cc:dd:ee:ff", строчные.
    pub bssid: String,
    pub ssid_bytes: Vec<u8>,
    /// дБм.
    pub rssi: i32,
    /// 0..100, оценка драйвера.
    pub link_quality: u32,
    pub freq_khz: u32,
    /// TU (1 TU = 1024 мкс).
    pub beacon_interval: u32,
    pub capability: u16,
    pub phy_type: u32,
    pub ie_raw: Vec<u8>,
    /// Вендор по OUI (заполняется снаружи, в ядре базы нет).
    pub vendor: Option<String>,
    pub info: BssInfo,
}

impl Bss {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bssid: &str,
        ssid_bytes: Vec<u8>,
        rssi: i32,
        link_quality: u32,
        freq_khz: u32,
        beacon_interval: u32,
        capability: u16,
        phy_type: u32,
        ie_raw: Vec<u8>,
    ) -> Bss {
        let info = parse_ies(&ie_raw);
        Bss {
            bssid: bssid.to_string(),
            ssid_bytes,
            rssi,
            link_quality,
            freq_khz,
            beacon_interval,
            capability,
            phy_type,
            ie_raw,
            vendor: None,
            info,
        }
    }

    /// Скрытый SSID: пустой или из одних нулей.
    pub fn hidden(&self) -> bool {
        self.ssid_bytes.iter().all(|&x| x == 0)
    }

    /// Имя сети; некорректный UTF-8 заменяется символом U+FFFD (как decode("utf-8", "replace")).
    pub fn ssid(&self) -> String {
        if self.hidden() {
            String::new()
        } else {
            String::from_utf8_lossy(&self.ssid_bytes).into_owned()
        }
    }

    pub fn ssid_display(&self) -> String {
        if self.hidden() {
            "<hidden>".into()
        } else {
            self.ssid()
        }
    }

    pub fn band(&self) -> &'static str {
        freq_to_band(self.freq_khz)
    }

    pub fn channel(&self) -> i32 {
        freq_to_channel(self.freq_khz)
    }

    /// Центр занимаемой полосы в номерах каналов. Для 20 МГц - основной канал.
    pub fn center_channel(&self) -> f64 {
        let i = &self.info;
        let w = i.width_mhz();
        let ch = self.channel();
        if i.he6_width.is_some() {
            if w == 20 {
                return ch as f64;
            }
            // в Python: ccfs1 if w >= 160 and ccfs1 else (ccfs0 or channel)
            return if w >= 160 && i.he6_ccfs1 != 0 {
                i.he6_ccfs1 as f64
            } else if i.he6_ccfs0 != 0 {
                i.he6_ccfs0 as f64
            } else {
                ch as f64
            };
        }
        let (s0, s1) = (i.vht_seg0 as i32, i.vht_seg1 as i32);
        if w >= 160 && s1 != 0 && (s1 - s0).abs() == 8 {
            return s1 as f64;
        }
        if w >= 80 && s0 != 0 {
            return s0 as f64;
        }
        if w == 40 {
            return (ch + if i.ht_sec_offset == 1 { 2 } else { -2 }) as f64;
        }
        ch as f64
    }

    /// Бит locally administered в первом октете BSSID (случайный адрес).
    pub fn locally_administered(&self) -> bool {
        u8::from_str_radix(self.bssid.get(..2).unwrap_or("00"), 16).unwrap_or(0) & 0x02 != 0
    }

    pub fn privacy_bit(&self) -> bool {
        self.capability & 0x0010 != 0
    }

    /// Защита сети одной строкой: WPA2-Personal, WPA2/WPA3-Personal, WPA2/3-Enterprise, OWE, Open, WEP, ...
    pub fn security(&self) -> String {
        const ENT: &[&str] = &[
            "802.1X",
            "FT-802.1X",
            "802.1X-SHA256",
            "Suite-B",
            "Suite-B-192",
            "FT-802.1X-SHA384",
            "802.1X-SHA384",
            "FILS-SHA256",
            "FILS-SHA384",
            "FT-FILS-SHA256",
            "FT-FILS-SHA384",
        ];
        const SAE: &[&str] = &["SAE", "FT-SAE", "SAE-EXT-KEY", "FT-SAE-EXT-KEY"];
        const PSK: &[&str] = &["PSK", "FT-PSK", "PSK-SHA256"];
        let i = &self.info;
        if let Some(rsn) = &i.rsn {
            let has = |set: &[&str]| rsn.akm.iter().any(|a| set.contains(&a.as_str()));
            let mut parts: Vec<&str> = vec![];
            if has(&["Suite-B-192", "FT-802.1X-SHA384"]) {
                parts.push("WPA3-Enterprise 192");
            } else if has(ENT) {
                parts.push(if rsn.mfp_required {
                    "WPA2/3-Enterprise"
                } else {
                    "WPA2-Enterprise"
                });
            }
            if has(SAE) {
                parts.push(if has(PSK) {
                    "WPA2/WPA3-Personal"
                } else {
                    "WPA3-Personal"
                });
            } else if has(PSK) {
                parts.push("WPA2-Personal");
            }
            if has(&["OWE"]) {
                parts.push("OWE");
            }
            let mut label = if parts.is_empty() {
                // как "RSN(" + ",".join(sorted(set(akm))) + ")"
                let mut akm: Vec<&str> = rsn.akm.iter().map(String::as_str).collect();
                akm.sort_unstable();
                akm.dedup();
                format!("RSN({})", akm.join(","))
            } else {
                parts.join("+")
            };
            if i.wpa1.is_some() {
                label.push_str("+WPA1");
            }
            return label;
        }
        if let Some(w) = &i.wpa1 {
            return if w.akm.iter().any(|a| a == "802.1X") {
                "WPA1-Enterprise"
            } else {
                "WPA1-Personal"
            }
            .into();
        }
        if self.privacy_bit() { "WEP" } else { "Open" }.into()
    }

    /// Pairwise-шифры RSN и WPA1 без повторов, в порядке появления.
    pub fn ciphers(&self) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        for r in [&self.info.rsn, &self.info.wpa1].into_iter().flatten() {
            for c in &r.pairwise {
                if !out.contains(c) {
                    out.push(c.clone());
                }
            }
        }
        out
    }

    pub fn generation_label(&self) -> String {
        match self.info.generation() {
            0 => "legacy".into(),
            6 if self.band() == "6" => "Wi-Fi 6E".into(),
            g => format!("Wi-Fi {g}"),
        }
    }
}

/// Снапшот скана: формат «Экспорт → JSON» (version 1).
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub taken_at: String,
    pub interface: String,
    pub bss: Vec<Bss>,
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("нечётная длина hex: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex: {e}")))
        .collect()
}

impl Snapshot {
    /// Чтение снапшота из JSON. Ошибка - понятным текстом (что и где не так).
    pub fn from_json(text: &str) -> Result<Snapshot, String> {
        let v = json::parse(text)?;
        let ver = v.get("version").and_then(Value::as_i64);
        if ver != Some(SNAPSHOT_VERSION) {
            return Err(format!("неподдерживаемая версия снапшота: {ver:?}"));
        }
        let s = |o: &Value, k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or(format!("нет поля {k}"))
        };
        let n = |o: &Value, k: &str| {
            o.get(k)
                .and_then(Value::as_i64)
                .ok_or(format!("нет числового поля {k}"))
        };
        let mut bss = vec![];
        for (idx, x) in v
            .get("bss")
            .and_then(Value::as_array)
            .ok_or("нет списка bss")?
            .iter()
            .enumerate()
        {
            let e = |m: String| format!("bss[{idx}]: {m}");
            bss.push(Bss::new(
                &s(x, "bssid").map_err(e)?,
                unhex(&s(x, "ssid_hex").map_err(e)?).map_err(e)?,
                n(x, "rssi").map_err(e)? as i32,
                n(x, "link_quality").map_err(e)? as u32,
                n(x, "freq_khz").map_err(e)? as u32,
                n(x, "beacon_interval").map_err(e)? as u32,
                n(x, "capability").map_err(e)? as u16,
                n(x, "phy_type").map_err(e)? as u32,
                unhex(&s(x, "ie_hex").map_err(e)?).map_err(e)?,
            ));
        }
        Ok(Snapshot {
            taken_at: s(&v, "taken_at")?,
            interface: v.get("interface").and_then(Value::as_str).unwrap_or("").to_string(),
            bss,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels() {
        assert_eq!((freq_to_band(2_412_000), freq_to_channel(2_412_000)), ("2.4", 1));
        assert_eq!(freq_to_channel(2_484_000), 14);
        assert_eq!((freq_to_band(5_180_000), freq_to_channel(5_180_000)), ("5", 36));
        assert_eq!((freq_to_band(5_885_000), freq_to_channel(5_885_000)), ("5", 177));
        assert_eq!((freq_to_band(5_935_000), freq_to_channel(5_935_000)), ("6", 2));
        assert_eq!((freq_to_band(5_955_000), freq_to_channel(5_955_000)), ("6", 1));
    }

    #[test]
    fn hidden_and_la() {
        let b = Bss::new(
            "02:11:22:33:44:55",
            vec![0, 0],
            -50,
            80,
            2_437_000,
            100,
            0x11,
            7,
            vec![],
        );
        assert!(b.hidden());
        assert_eq!(b.ssid_display(), "<hidden>");
        assert!(b.locally_administered());
        assert_eq!(b.security(), "WEP");
    }
}
