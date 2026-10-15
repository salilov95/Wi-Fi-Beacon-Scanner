//! Строка таблицы сетей - то, что окно получает про каждый BSS.
//!
//! Повторяет `bss_to_dict()` из `wifi_beacon_scanner/web/state.py`: те же поля, в том же порядке.
//! Поля `std` (пояснения к дополнениям 802.11) и `ie_tree` (вкладка Beacon) - на текущем языке потока.

use crate::amend::standards;
use crate::describe::describe_ies;
use crate::ie::round1;
use crate::json::Value;
use crate::mcs::capability;
use crate::model::Bss;

/// Поля строки, которые уже считает ядро на Rust (в порядке `bss_to_dict`).
pub const FIELDS: &[&str] = &[
    "bssid",
    "ssid",
    "hidden",
    "vendor",
    "random_mac",
    "band",
    "channel",
    "center",
    "width",
    "rssi",
    "quality",
    "security",
    "ciphers",
    "akm",
    "pmf",
    "wps",
    "gen",
    "gen_n",
    "streams",
    "phy",
    "mcs",
    "nss",
    "rate",
    "bss_color",
    "k",
    "nr",
    "r",
    "v",
    "std",
    "mdid",
    "util",
    "stations",
    "country",
    "beacon",
    "dtim",
    "cap",
    "ht_prot",
    "ie_len",
    "ie_tree",
];

/// Строка таблицы для одного BSS.
pub fn bss_row(b: &Bss) -> Value {
    let i = &b.info;
    let cap = capability(i);
    let pmf = match &i.rsn {
        None => "",
        Some(r) if r.mfp_required => "required",
        Some(r) if r.mfp_capable => "capable",
        Some(_) => "no",
    };
    let row: Vec<(&str, Value)> = vec![
        ("bssid", b.bssid.as_str().into()),
        ("ssid", b.ssid_display().into()),
        ("hidden", b.hidden().into()),
        ("vendor", b.vendor.clone().unwrap_or_default().into()),
        ("random_mac", b.locally_administered().into()),
        ("band", b.band().into()),
        ("channel", b.channel().into()),
        ("center", b.center_channel().into()),
        ("width", i.width_mhz().into()),
        ("rssi", b.rssi.into()),
        ("quality", b.link_quality.into()),
        ("security", b.security().into()),
        ("ciphers", b.ciphers().into()),
        ("akm", i.rsn.as_ref().map(|r| r.akm.clone()).unwrap_or_default().into()),
        ("pmf", pmf.into()),
        ("wps", i.wps.into()),
        ("gen", b.generation_label().into()),
        ("gen_n", i.generation().into()),
        ("streams", i.max_streams().into()),
        ("phy", cap.phy.into()),
        ("mcs", cap.mcs.into()),
        ("nss", cap.nss.into()),
        ("rate", cap.rate.map(round1).into()),
        ("bss_color", i.he_bss_color.into()),
        ("k", i.dot11k().into()),
        ("nr", i.neighbor_report().into()),
        ("r", i.dot11r().into()),
        ("v", i.dot11v().into()),
        (
            "std",
            Value::Obj(
                standards(b)
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.into()))
                    .collect(),
            ),
        ),
        ("mdid", i.mdid.into()),
        ("util", i.qbss_util_pct.into()),
        ("stations", i.qbss_stations.into()),
        ("country", i.country.clone().unwrap_or_default().into()),
        ("beacon", b.beacon_interval.into()),
        ("dtim", i.dtim_period.into()),
        ("cap", format!("0x{:04X}", b.capability).into()),
        ("ht_prot", i.ht_protection.into()),
        ("ie_len", b.ie_raw.len().into()),
        (
            "ie_tree",
            Value::Arr(describe_ies(&b.ie_raw).iter().map(|n| n.to_value()).collect()),
        ),
    ];
    debug_assert_eq!(row.iter().map(|(k, _)| *k).collect::<Vec<_>>(), FIELDS);
    Value::Obj(row.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
