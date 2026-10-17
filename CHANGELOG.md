# Changelog

**English** · [Русский](CHANGELOG.ru.md)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- New look of the HTML and PDF report: a channel map per band at the top (each BSS drawn as its occupied
  bandwidth, height is the signal, your SSIDs in colour, the DFS range shaded), problem counters, a list of
  sections, problems as "what is wrong / what to check / affected BSSs", event badges in the connection journal,
  all BSSs grouped by network (your SSIDs first). The capture time is written out in words; the English report
  no longer has Russian headings.
- Excel report: header row in the app colour, banded rows, critical and warning problems in colour, readable
  column names on the BSS sheet, landscape printing fitted to the page width. The data is the same as before.

### Development
- `tools/compare_state.py` checks reports by content: everything the 1.x report contains (BSSs, problem texts,
  journal and sessions, survey points) is in the 2.x HTML, and the Excel cell values match 1.x.

## [2.0.0] - 2026-10-17

Version 2 is the same app rewritten in Rust + Tauri 2: its own window instead of a local server and an Edge window,
with every feature of 1.1. The interface, tabs, analysis and reports are the same; the results match 1.1 on the
reference scans in `contract/`.

### Changed
- The app has its own window (WebView2, built into Windows 10/11). There is no local server on `127.0.0.1`, no open
  port and no Edge window; links to GitHub open in the default browser.
- Files: `WiFiBeaconScanner2-Setup-2.0.0.exe` (installer for the current user, no administrator rights; silent
  install `/S`) and the portable `WiFiBeaconScanner2.exe`. Version 2 installs next to 1.x and does not change it.
- Settings are in `%APPDATA%\WiFiBeaconScanner2`, the log in `%LOCALAPPDATA%\WiFiBeaconScanner2\logs\app.log`.
  While version 2 has no settings of its own, it starts with the 1.x settings (theme, columns, "My SSIDs",
  language); the 1.x file is never changed.
- README screenshots are in the dark theme.

### Removed
- The command line `interfaces`, `scan`, `analyze` and the window options `--port`, `--no-browser`, `--keep-running`
  stay in 1.x (`python -m wifi_beacon_scanner`); version 2 ignores the last three. `--demo`, `--ssid`, `--manuf` and
  `--lang` work as before (`--ssid=CORP` too).

### Development
- `rust/`: the `wbs-core` crate (everything except the window, no external crates; Windows APIs through `raw-dylib`)
  and the Tauri 2 shell `rust/app`. Workflow `.github/workflows/rust.yml`: rustfmt, clippy and tests on Windows and
  Linux, a PDF printed with the real Edge, the Windows event log and the update check on a Windows runner, the window
  build, a start-up check, silent install and uninstall; releases with "Run workflow → publish" on `main`.
- `contract/`: reference output on fixed scans (network rows with the IE tree, problems, channels, both languages),
  connection journal and session scenarios (`contract/journal`), a real anonymised scan, synthetic coverage and the
  demo office. `tools/compare_state.py` compares the Rust API with 1.x: state, CSV/JSON exports, HTML byte for byte,
  Excel part by part, the survey and view settings. Also `tools/anonymize_snapshot.py`, `tools/journal_contract.py`,
  `tools/make_contract_fixtures.py`, `tools/screenshots.py`.
- 1.x moves to the `1.x` branch: fixes are released there with `v1.*` tags and do not become the latest release.

## [1.1.0] - 2026-10-14

### Added
- The app in English and Russian: interface, tabs, problems and hints, beacon decoding, sessions, PDF/Excel/HTML
  and CSV reports. The language follows the Windows display language and can be switched in View → Language;
  the choice is saved with the other settings. `--lang en|ru` sets it from the command line.
- English screenshots in `README.md`; Russian screenshots in `README.ru.md` updated to the current version.
- `tools/i18n_scan.py` and `tests/test_i18n.py`: no string is left without a translation.
- Documentation in English: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md` and `docs/en/`; the Russian versions
  are `README.ru.md`, `CHANGELOG.ru.md`, `CONTRIBUTING.ru.md` and `docs/ru/`, with a language switch on every page.
- `SECURITY.md` and `CODE_OF_CONDUCT.md`; bilingual issue and pull request templates.
- Release notes are built from both changelogs (English first, then Russian).

### Fixed
- Survey layer summary: a point without signal is shown as "no signal" rather than "no dBm".

## [1.0.1] - 2026-10-11

### Fixed
- Supported Rates / Extended Supported Rates: BSS membership selector values (HT PHY, VHT PHY, SAE H2E only,
  HE PHY, EHT PHY etc.) are no longer treated as rates. Previously the Beacon tab showed non-existent
  "63.5* 61.5* Mbit/s", and a legacy AP with a selector got an inflated rate. Selectors are shown as a separate
  field; the "SAE H2E only" flag is now visible.
- Channel width from VHT Operation in the deprecated encoding (2 = 160 MHz, 3 = 80+80 MHz): such APs were shown
  as 40 MHz, which affected the PHY rate, the channel chart and the channel ranking.
- AKM 14-17 (FILS), 23 (802.1X SHA-384), 24 (SAE-EXT-KEY) and 25 (FT-SAE-EXT-KEY) are recognized by name.
  WPA3-Personal on SAE-EXT-KEY (Wi-Fi 7) used to be shown as `RSN(type24)`, and PSK + SAE-EXT-KEY as
  WPA2-Personal; now they are WPA3-Personal and WPA2/WPA3-Personal.
- 6 GHz channel 2 (5935 MHz) was shown as channel −3.

### Changed
- Several SSIDs of one radio count as one transmitter in "Many BSSs on one channel" (`RF_COCHANNEL`), in the
  channel ranking and in "High channel utilization" (`RF_UTIL`). One AP with 4 SSIDs no longer triggers the
  neighbors warning, power on the channel is no longer overestimated (it was +6 dB with 4 SSIDs), and load is
  reported once per radio. A radio = same channel, width and center, BSSIDs differ only in the lower 4 bits of the
  last octet. If BSSIDs are assigned differently, BSSs are treated as separate radios, as before.
- Measurement history no longer grows without bound during a long survey: a BSSID absent from the last 240 scans
  and not heard for more than 30 minutes is dropped. Nothing disappears from the charts - they never look deeper
  than 240 scans.

## [1.0.0] - 2026-10-11

### Added
- Columns of the network table can be resized: drag a header border, double-click to fit the content. Widths are
  remembered; View → "Reset column widths" restores automatic layout.
- A "Windows log" tab separate from Sessions. The WLAN-AutoConfig log for the last day loads on start and refreshes
  every minute; period 24 h / 3 days / week, filters by stage (connection, association, security / 4-way, 802.1X)
  and level, a summary (connections 8001, failures 8002, disconnects 8003, 802.1X errors 12013), most frequent
  reasons, event fields on click, CSV export. The number of errors in the last day is shown on the tab label.
- Session details list Windows log events around the session (from 3 s before the start to 10 s after the end).
- View → About: version, data source, log path; "Check for updates" (only on click, a request to GitHub Releases).

### Changed
- The console of the portable version shows warnings and errors only; details go to `app.log`.
- A quieter app log: first scan, empty scans, recovery after an error, the same error in a row logged once,
  a scan summary every 10 minutes.

## [0.9.0] - 2026-10-11

### Added
- Sessions tab: a client state machine driven by Windows notifications. Every connection and roam is broken down
  into stages (association, 802.1X/4-way authentication, IPv4) with durations and a timeline.
- 802.1X: subscription to ONEX notifications - authentication result, failure reason, EAP error code, EAP type,
  machine or user credentials, restarts.
- DHCP: time from connection to a new lease (DORA), address, DHCP server, APIPA (GetAdaptersInfo).
- Windows WLAN-AutoConfig/Operational log for 24 hours, 3 days or a week, with event text from Windows.
- Sessions in CSV and in PDF/HTML/Excel reports.
- CI on Windows checks GetAdaptersInfo and event log reading on a real system.
- 802.11 amendments from beacons: d, e, h, i, k, r, u, v, w, mc, ai, s, TWT, Multiple BSSID, Hotspot 2.0.
  An "802.11" column instead of "k·r·v", an "802.11" filter (has / has none of the selected), rows on the Beacon
  tab, a `standards` column in CSV and Excel, a column in HTML/PDF, a field in Compare. Decoding of IEs 12, 32,
  35, 37, 71, 107, 108, 111, 114 and all known Extended Capabilities bits.
- App log file: `%LOCALAPPDATA%\WiFiBeaconScanner\logs\app.log` - start-up, every scan (BSS count, WlanScan code),
  errors, page errors. View → "Open log folder".

### Fixed
- The first start showed "No data yet" until "Scan" was clicked: the first scan returned an empty list and was not
  retried. Likely cause - the location consent prompt Windows 11 24H2 shows on the first scan
  (`ERROR_ACCESS_DENIED`), or a scan cache that was not ready yet. Now the first scan starts right at launch, an
  empty list is re-read for up to 6 s, access denial is shown as a clear banner with an "Open location settings"
  button, and auto-scan retries by itself.
- If Edge relaunched its window on the first start with a new profile, the app considered the window closed.
  Now after the Edge process exits the app waits a few seconds and keeps running if the page is alive.

### Changed
- Auto-scan is on by default, every 5 s; the choice is remembered.
- The Sessions and Compare tabs moved to the right.

## [0.8.0] - 2026-10-11

### Fixed
- The app exited while its window was minimized: Edge put the page to sleep, polling stopped, and after 15 minutes
  of silence the app considered the window closed (and after 5 seconds if the page was unloaded from memory).
  Now the app opens its own Edge window with a separate profile and without background throttling, and exits only
  when the window process itself is closed. Silence from a minimized window is no longer treated as closing.

### Changed
- The "Findings" tab is now called "Problems" (also in PDF/HTML/Excel reports); README screenshots updated.
- The connection journal can show the last minute (1, 5, 15, 30 min).

## [0.7.1] - 2026-10-11

### Changed
- README rewritten: features, screenshots, installation; details moved to `docs/`
  (diagnostics, connection journal, installation and deployment, development).
- The space before the value in the signal chart legend is back.

### Added
- Issue and pull request templates, CONTRIBUTING.md.

## [0.7.0] - 2026-10-08

### Changed
- The app is now called **Wi-Fi Beacon Scanner**: package `wifi_beacon_scanner`, `WiFiBeaconScanner.exe`,
  installer `WiFiBeaconScanner-Setup-<version>.exe`, settings folder `%APPDATA%\WiFiBeaconScanner`.
  Settings of the previous version (`%APPDATA%\WifiDiag`) are picked up on first start.

### Fixed
- PDF export did not work on Windows: after printing, Edge kept files of the temporary profile open, deleting the
  folder failed and the window waited forever. Now the app waits for the finished file, closes the Edge processes
  and cleans up the folder without errors. If printing still fails, the reason is shown and there is a fallback:
  open the report and save it as PDF with Ctrl+P.
- Export error messages disappeared after a second: the state refresh erased them.

### Added
- MIT license, CHANGELOG, `pyproject.toml` (the `wifi-beacon-scanner` command after `pip install .`).
- GitHub Actions: tests on Windows and Linux on every push (on Windows also PDF printing with the real Edge);
  Release builds the exe and the installer, checks the built exe (start-up, scan, PDF and Excel export)
  and publishes them with checksums in Releases.

## 0.6.0 - 2026-10-08 (as WifiDiag, not published)

### Added
- MCS parsing from beacons: HT/VHT/HE Capabilities and Operation, Basic MCS, Short GI, BSS Color, channel width
  and center on 6 GHz. "Max MCS" and "Max PHY" columns, MCS estimate for the own connection from its rate.
- One red-to-green signal scale across all tabs and reports, color scales in Excel.
- Inno Setup installer (silent install for mass deployment), icon, version in the exe properties.
- The app exits by itself when the window is closed; app log in `%LOCALAPPDATA%`.

## 0.5.0 - 2026-10-08 (as WifiDiag, not published)

### Added
- First version: scanning via the Native Wifi API, IE parsing, diagnostic rules, a tabbed UI (channels, overview,
  utilization, signal over time, connection journal, floor plan survey, findings, beacon, compare), PDF/Excel/
  HTML/CSV/JSON reports, color themes.

[Unreleased]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v2.0.0
[1.1.0]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v1.1.0
[1.0.1]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v1.0.1
[1.0.0]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v1.0.0
[0.9.0]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v0.9.0
[0.8.0]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v0.8.0
[0.7.1]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v0.7.1
[0.7.0]: https://github.com/salilov95/Wi-Fi-Beacon-Scanner/releases/tag/v0.7.0
