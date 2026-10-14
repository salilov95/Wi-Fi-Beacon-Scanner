# Diagnostics: what is checked and where the numbers come from

[← README](../../README.md) · [Русский](../ru/diagnostics.md)

## What is checked (the Problems tab)

29 checks in total. In the app every problem comes with an explanation and a "what to check" hint.

### Security

| Code | What it finds | Severity |
|---|---|---|
| `SEC_OPEN` | Open network without encryption | warning |
| `SEC_WEP` | WEP | critical |
| `SEC_WPA1_ONLY` | WPA1 only | critical |
| `SEC_WPA1_MIXED` | WPA1 compatibility mode enabled | warning |
| `SEC_TKIP` | TKIP cipher allowed | warning |
| `SEC_NO_PMF` | Management frame protection (PMF/802.11w) not enabled | info |
| `SEC_TRANSITION` | WPA2/WPA3 transition mode | info |
| `SEC_WPS` | WPS enabled | info |

### Roaming and consistency of BSSs within one network

| Code | What it finds | Severity |
|---|---|---|
| `ROAM_SEC_MISMATCH` | Different security settings on BSSs of one SSID | warning |
| `ROAM_COUNTRY_MISMATCH` | Different country codes on BSSs of one SSID | warning |
| `ROAM_TIMERS` | Different beacon interval / DTIM on BSSs of one SSID | info |
| `ROAM_11R_PARTIAL` | 802.11r (FT) enabled on some BSSs of the network only | warning |
| `ROAM_11K_PARTIAL` | 802.11k enabled on some BSSs of the network only | warning |
| `ROAM_11V_PARTIAL` | 802.11v enabled on some BSSs of the network only | warning |
| `ROAM_11R_OFF` | 802.11r not advertised on an Enterprise network | info |
| `ROAM_11K_OFF` | 802.11k not advertised | info |
| `ROAM_11V_OFF` | 802.11v not advertised | info |

### RF

| Code | What it finds | Severity |
|---|---|---|
| `RF_WEAK` | Weak signal | warning |
| `RF_UTIL` | High channel utilization | warning / critical |
| `RF_COCHANNEL` | Many BSSs on one channel | warning |
| `RF_24_NONSTD` | 2.4 GHz: channel other than 1/6/11 | warning |
| `RF_24_40MHZ` | 2.4 GHz: 40 MHz channel width | warning |
| `RF_24_OVERLAP` | 2.4 GHz: strong BSSs on overlapping channels | warning |
| `RF_DFS` | 5 GHz: DFS channels in use | info |

### Network hygiene

| Code | What it finds | Severity |
|---|---|---|
| `HYG_BASIC_RATES` | 2.4 GHz: 802.11b rates in the basic rate set | info |
| `HYG_HT_PROT` | HT protection enabled | info |
| `HYG_LEGACY_PHY` | BSS without HT (802.11a/b/g only) | warning |
| `HYG_24_ONLY` | SSID heard on 2.4 GHz only | info |
| `HYG_HIDDEN` | Hidden SSIDs | info |

`RF_COCHANNEL`, `RF_UTIL` and the channel ranking count radios, not BSSIDs: several SSIDs of one AP are one
transmitter. A radio is a set of BSSs on the same channel, width and center frequency whose BSSIDs differ only
in the lower 4 bits of the last octet (Multiple BSSID and the address assignment used by most vendors). If a
vendor assigns BSSIDs differently, such BSSs are counted as separate radios.

Thresholds live in `Thresholds` (`wifi_beacon_scanner/rules.py`); from the CLI only `--weak-rssi` can be changed
for now.

Problems are searched across the whole air. Configuration and weak-signal problems are reported only for
"My SSIDs"; other networks count as channel interference. A report includes the problems that concern the
selected networks.

## 802.11 amendments (column and filter)

What an AP advertises in beacons / probe responses. These are declared capabilities, not a test that they work.

| Code | Source |
|---|---|
| d | Country IE (7) |
| e | WMM (vendor IE 00-50-F2 type 2), EDCA Parameter Set (12) or the QoS bit in Capability Information |
| h | Spectrum Management bit in Capability Information, Power Constraint (32), TPC Report (35), Channel Switch Announcement (37) |
| i | RSN IE (48) |
| k | RM Enabled Capabilities (70), plus whether neighbor report is supported |
| r | Mobility Domain (54), MDID and FT over DS |
| u | Interworking (107) or Extended Capabilities bit 31; network type, "internet" flag, ANQP (108), Roaming Consortium (111) |
| v | Extended Capabilities bit 19 (BSS Transition); also Proxy ARP, WNM Sleep, TFS, DMS, TIM Broadcast, WNM Notification |
| w | PMF in RSN Capabilities: capable (MFPC) or required (MFPR) |
| mc | FTM responder / initiator, Extended Capabilities bits 70/71 |
| ai | FILS, Extended Capabilities bit 72 |
| s | Mesh ID (114) |
| TWT | HE MAC Capabilities (TWT Responder) or Extended Capabilities bit 78 |
| MBSSID | Multiple BSSID (71) or Extended Capabilities bit 22 |
| HS2.0 | Hotspot 2.0 Indication (vendor IE 50-6F-9A type 0x10) |

The "802.11" filter in the filter bar: "has all selected" or "has none of the selected", with the number of BSSs
advertising each item. All Extended Capabilities bits that are set are listed on the Beacon tab.

## Signal scale

One red-to-green scale everywhere: −85 dBm and below red, −75 orange, −67 yellow, −60 light green, −50 and above
green. Rules of thumb: −67 and stronger is enough for voice and video, −67…−72 for data; below −75 clients start
losing rate and roaming. Channel load is colored the other way round: up to 30% free, 30–50% moderate,
50–70% high, 70% and above overloaded.

## Channel load

Taken from QBSS Load (IE 11) in beacons: the share of time the AP itself considers the channel busy, and the
number of stations. Not every AP advertises it: no IE means no number, not "0%". Per channel the maximum among the
APs that report load is used.

## MCS and maximum rate

A beacon does not contain the "current MCS". It contains what the AP is capable of:

- HT Capabilities: Rx MCS bitmask (for example MCS 0-15 = 2 streams), Short GI 20/40;
- VHT Capabilities: Rx/Tx VHT-MCS map per stream (MCS 0-7/0-8/0-9), Short GI 80/160, widths above 80 MHz, beamforming;
- HE Capabilities: Rx/Tx HE-MCS map up to 80 MHz and for 160 MHz (MCS 0-7/0-9/0-11);
- HT/VHT/HE Operation: Basic MCS Set - the minimum the AP requires from every client; HE Operation also carries
  BSS Color and, for 6 GHz, the channel width and center.

"Max PHY" is computed from this: the PHY rate given by the standard's formula for the highest MCS, the AP's number
of streams, the operating channel width and the shortest GI the AP supports. It is a ceiling for a perfect signal
and a client with the same number of streams, not throughput (TCP will be roughly half of it).

The MCS actually used for frames is only visible in monitor mode (radiotap); the Native Wifi API does not expose it.
For its own connection Windows reports the Rx and Tx rates; the app finds the MCS, stream count, width and GI that
give exactly that rate (Connection tab, "MCS from rate"). There can be several matches (MCS 4 on 2 streams and
MCS 8 on 1 stream are almost equal); the variant with the BSS width and two streams is shown first, the others in
the tooltip. EHT (Wi-Fi 7) MCS is not parsed yet: for such APs the HE ceiling is shown.

## Vendors (the Vendor column)

Requires the `manuf` file from Wireshark. It is looked up automatically in `wifi_beacon_scanner/data/manuf`,
`C:\Program Files\Wireshark\manuf`, `C:\Program Files (x86)\Helge Keck\WinFi\vendors.txt`;
otherwise pass `--manuf path`. Release builds include it.
