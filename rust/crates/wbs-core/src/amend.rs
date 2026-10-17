//! Какие дополнения 802.11 объявляет точка доступа: d, e, h, i, k, r, u, v, w и несколько функций сверх них.
//!
//! Перенос `wifi_beacon_scanner/amend.py`. Всё берётся из beacon: Capability Information и IE.
//! Это объявленные возможности, а не проверка того, что они реально работают.

use crate::describe::access_network_type;
use crate::i18n::{tr, trf};
use crate::model::Bss;

const CAP_SPECTRUM_MGMT: u16 = 1 << 8; // 802.11h
const CAP_QOS: u16 = 1 << 9; // 802.11e

/// (код, подпись в таблице, полное название - ключ перевода)
pub const STANDARDS: &[(&str, &str, &str)] = &[
    ("d", "d", "802.11d - код страны и разрешённые каналы"),
    ("e", "e", "802.11e - QoS (WMM / EDCA)"),
    ("h", "h", "802.11h - DFS/TPC: управление спектром и мощностью"),
    ("i", "i", "802.11i - RSN (WPA2/WPA3)"),
    ("k", "k", "802.11k - Radio Measurement, neighbor report"),
    ("r", "r", "802.11r - Fast BSS Transition (FT)"),
    ("u", "u", "802.11u - Interworking"),
    ("v", "v", "802.11v - BSS Transition Management"),
    ("w", "w", "802.11w - PMF, защита management-кадров"),
    ("mc", "mc", "802.11mc - FTM, измерение расстояния (RTT)"),
    ("ai", "ai", "802.11ai - FILS, быстрая первичная аутентификация"),
    ("s", "s", "802.11s - mesh"),
    ("twt", "TWT", "TWT - Target Wake Time (802.11ax)"),
    ("mbssid", "MBSSID", "Multiple BSSID: несколько SSID в одном beacon"),
    ("hs", "HS2.0", "Hotspot 2.0 / Passpoint"),
];

fn join_nonempty(parts: Vec<String>) -> Option<String> {
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn explain(code: &str, b: &Bss) -> Option<String> {
    let i = &b.info;
    match code {
        "d" => i.country.as_ref().map(|c| trf("страна %s", &[c.into()])),
        "e" => {
            let mut p = vec![];
            if i.wmm {
                p.push("WMM".to_string());
            }
            if i.edca {
                p.push("EDCA".to_string());
            }
            if b.capability & CAP_QOS != 0 {
                p.push(tr("QoS в Capability"));
            }
            join_nonempty(p)
        }
        "h" => {
            let mut p = vec![];
            if b.capability & CAP_SPECTRUM_MGMT != 0 {
                p.push("Spectrum Management".to_string());
            }
            if let Some(pc) = i.power_constraint {
                p.push(trf("Power Constraint %d дБ", &[pc.into()]));
            }
            if let Some(tx) = i.tpc_tx_power {
                p.push(trf("TPC Report %d дБм", &[tx.into()]));
            }
            if i.csa {
                p.push(tr("объявлена смена канала (CSA)"));
            }
            join_nonempty(p)
        }
        // в Python: ", ".join(akm) or "RSN" if rsn else None
        "i" => i.rsn.as_ref().map(|r| {
            if r.akm.is_empty() {
                "RSN".to_string()
            } else {
                r.akm.join(", ")
            }
        }),
        "k" => {
            if !i.dot11k() {
                None
            } else if i.neighbor_report() {
                Some("neighbor report".into())
            } else {
                Some(tr("без neighbor report"))
            }
        }
        "r" => i
            .mdid
            .map(|m| format!("MDID 0x{m:04X}{}", if i.ft_over_ds { ", FT over DS" } else { "" })),
        "u" => {
            if i.interworking.is_none() && !i.ext_bit(31) {
                return None;
            }
            let mut p = vec![];
            if let Some(iw) = i.interworking {
                let t = iw & 0x0f;
                let name = access_network_type(t).map(tr).unwrap_or_default();
                p.push(if name.is_empty() {
                    trf("тип %d", &[t.into()])
                } else {
                    name
                });
                if iw & 0x10 != 0 {
                    p.push(tr("интернет"));
                }
            }
            if i.anqp {
                p.push("ANQP".into());
            }
            if i.roaming_consortium {
                p.push("Roaming Consortium".into());
            }
            Some(join_nonempty(p).unwrap_or_else(|| "Interworking".into()))
        }
        "v" => {
            if !i.dot11v() {
                return None;
            }
            const EXTRA: &[(usize, &str)] = &[
                (12, "Proxy ARP"),
                (17, "WNM Sleep"),
                (16, "TFS"),
                (26, "DMS"),
                (18, "TIM Broadcast"),
                (46, "WNM Notification"),
            ];
            let extra: Vec<&str> = EXTRA
                .iter()
                .filter(|(bit, _)| i.ext_bit(*bit))
                .map(|(_, n)| *n)
                .collect();
            Some(if extra.is_empty() {
                "BTM".into()
            } else {
                format!("BTM, {}", extra.join(", "))
            })
        }
        "w" => match &i.rsn {
            Some(r) if r.mfp_capable || r.mfp_required => Some(tr(if r.mfp_required {
                "обязательна"
            } else {
                "поддерживается"
            })),
            _ => None,
        },
        "mc" => {
            let mut p = vec![];
            if i.ext_bit(70) {
                p.push("responder");
            }
            if i.ext_bit(71) {
                p.push("initiator");
            }
            if p.is_empty() {
                None
            } else {
                Some(format!("FTM {}", p.join(", ")))
            }
        }
        "ai" => i.ext_bit(72).then(|| "FILS".to_string()),
        "s" => i.mesh_id.as_ref().map(|m| {
            let t = String::from_utf8_lossy(m).into_owned();
            format!("Mesh ID {}", if t.is_empty() { tr("(пусто)") } else { t })
        }),
        "twt" => i.twt_responder().then(|| "TWT responder".to_string()),
        "mbssid" => (i.multi_bssid || i.ext_bit(22)).then(|| "Multiple BSSID".to_string()),
        "hs" => i.hs20.then(|| "Passpoint".to_string()),
        _ => None,
    }
}

/// Строка для CSV и отчётов: «d e h i k r v w TWT» (`short` в 1.x).
pub fn short(std: &[(&str, String)]) -> String {
    STANDARDS
        .iter()
        .filter(|(c, _, _)| std.iter().any(|(k, _)| k == c))
        .map(|(_, label, _)| *label)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `[(код, пояснение)]` только для объявленных точкой дополнений, в порядке STANDARDS.
pub fn standards(b: &Bss) -> Vec<(&'static str, String)> {
    STANDARDS
        .iter()
        .filter_map(|(code, _, _)| explain(code, b).filter(|s| !s.is_empty()).map(|s| (*code, s)))
        .collect()
}
