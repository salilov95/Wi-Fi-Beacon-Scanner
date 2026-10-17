# Development, build and release

[← README](../../README.md) · [Русский](../ru/development.md)

## Version 2 (Rust + Tauri 2)

The app lives in `rust/`:

    rust/crates/wbs-core/        everything except the window, no external crates (builds and tests on any OS)
      src/ie.rs model.rs mcs.rs describe.rs amend.rs rules.rs row.rs   beacon parsing and analysis
      src/conn.rs session.rs onex.rs                                   connection journal, sessions, 802.1X
      src/report.rs xlsx.rs zip.rs pdf.rs                              HTML/CSV/JSON/Excel reports, PDF via Edge
      src/survey.rs demo.rs diff.rs prefs.rs                           survey, demo mode, comparison, view settings
      src/i18n.rs json.rs xml.rs update.rs clock.rs oui.rs             languages, JSON/XML, update check, time, vendors
      src/app.rs                                                       state and the /api/* routes of the window
      src/win.rs win_conn.rs win_log.rs                                Windows: wlanapi, notifications, iphlpapi, wevtapi, WinHTTP
      examples/devserver.rs                                            the same API over HTTP (tests, screenshots)
      tests/                                                           API, golden files, journal scenarios
    rust/app/                    Tauri 2 window: main.rs, build.rs (embeds the vendor database), tauri.conf.json
    wifi_beacon_scanner/web/static/   UI, shared with 1.x and embedded into the exe
    contract/                    golden files: what both versions must output on fixed scans
    tools/compare_state.py       2.x API against 1.x: state, exports, reports, survey, settings
    tools/screenshots.py         README screenshots from the devserver in demo mode

The window opens `http://wbs.localhost/`, which is not a network address: Tauri hands every request of the page to
the app through the custom `wbs` protocol, and `wbs_core::app::App::handle` answers with the same JSON as the 1.x
server. That is why parity with 1.x is checked by comparing API answers (`tools/compare_state.py`).

### Build and tests

The core builds anywhere with Rust (stable; CI uses the version pinned in `.github/workflows/rust.yml`):

    cd rust
    cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
    RUSTFLAGS="--cfg wbs_check_win" cargo clippy --target-dir target/wincheck --all-targets   # Windows modules, on Linux
    cargo build --example devserver && python ../tools/compare_state.py target/debug/examples/devserver

The window and the installer build on Windows with Rust and Node.js:

    cd rust/app
    npx @tauri-apps/cli@2 build      # target/release/wbs-app.exe and target/release/bundle/nsis/*-setup.exe

With `WBS_MANUF=<path to the Wireshark manuf file>` the vendor database is embedded into the exe.

Demo without Wi-Fi: `WiFiBeaconScanner2.exe --demo`, or the devserver on any OS:
`WBS_BACKEND=demo cargo run --example devserver -- ../contract/fixtures/demo-base.json 8765`, then
`http://127.0.0.1:8765/`.

### Releasing a version

1. Bump the version in `rust/app/tauri.conf.json`, `rust/app/Cargo.toml` and `rust/crates/wbs-core/Cargo.toml`;
   add a section to [CHANGELOG.md](../../CHANGELOG.md) and [CHANGELOG.ru.md](../../CHANGELOG.ru.md).
2. Pull request into `main`. The [Rust](../../.github/workflows/rust.yml) workflow runs the checks on Windows and
   Linux, builds the window and the installer, starts the exe, installs and uninstalls it silently, and attaches a
   draft pre-release with the files for testing.
3. After merging: Actions → Rust → Run workflow on `main` with "publish". The workflow builds and checks again and
   publishes release `v<version>` with notes from both changelogs; the tag is created on the built commit. A version
   with a hyphen (`2.1.0-rc.1`) is published as a pre-release and does not become the latest.
4. Fixes for 1.x: branch `1.x`, version in `wifi_beacon_scanner/__init__.py`, then a `v1.x.y` tag or Actions →
   Release 1.x on that branch. Such a release does not become the latest.

`tools/screenshots.py` (Playwright and Pillow, only for this script) retakes the README screenshots in the dark
theme: `docs/images` (Russian) and `docs/images/en`.

## Translations

The source language is Russian, and a Russian string is its own translation key.

- Python: user-visible text goes through `tr("…")` (`wifi_beacon_scanner/i18n.py`); strings in module-level
  tables are marked `N_("…")` and passed through `tr()` where they are shown. Format after translating:
  `tr("слабый сигнал %d дБм") % rssi`. Translations live in `wifi_beacon_scanner/i18n_en.py` with the same
  `%s`/`%d` in the same order.
- Page: `T('…', {name: value})` in `app.js`, translations in `web/static/i18n.js`; static text of `index.html`
  is translated on load. Switching the language reloads the page.
- `python tools/i18n_scan.py missing` and `python tools/i18n_scan.py js` list strings without a translation,
  `report` shows Cyrillic text outside `tr()`. `tests/test_i18n.py` fails if a translation is missing or loses
  a placeholder.

## Version 1.x (Python): the reference implementation

Version 1.x stays in the repository: `wifi_beacon_scanner/` is the reference that the golden files in `contract/`
are generated from, and the `1.x` branch is where 1.x fixes are released. Below is how to run and build it.

### Running from source

Requires Python 3.8+ for Windows, no external dependencies.

    python -m wifi_beacon_scanner gui --ssid NETWORK_NAME   # window
    python -m wifi_beacon_scanner gui --demo                # demo data, also works outside Windows
    pip install .  &&  wifi-beacon-scanner gui              # as a package

### Command line: first run step by step

**1. Make sure the tests pass on your machine**

    python -m unittest discover -s tests

You should see `OK` at the end (some tests are skipped without Chromium or LibreOffice). Why: this confirms the
parser behaves the same on your machine before you trust the scan results.

**2. Make sure the adapter is visible**

    python -m wifi_beacon_scanner interfaces

Expect a line like `0: Intel(R) Wi-Fi 6 AX201 ...`. If it is empty or fails, there is nothing to scan with and
no point going further.

**3. First scan, only save the raw data**

    python -m wifi_beacon_scanner scan --save snap.json

Why `--save` first: the snapshot contains the raw IE bytes, so parsing can be reproduced on any OS and parser bugs
can be found on real data. If the output says `BSS в эфире: 0` (0 BSSs on air) while networks are definitely
around, see the limitations in [Installation and deployment](deployment.md#limitations).

**4. A proper report for your own network**

    python -m wifi_beacon_scanner scan --ssid NETWORK_NAME --html report.html --csv bss.csv --save snap.json

Open `report.html`. `--ssid` can be given several times: configuration and weak-signal problems are reported only
for these networks; other networks count as channel interference.

**5. Analyze a snapshot without scanning (any OS)**

    python -m wifi_beacon_scanner analyze snap.json --ssid NETWORK_NAME --html report.html

### Build (1.x)

The version is defined in one place: `wifi_beacon_scanner/__init__.py`. Changes are described in two languages:
[CHANGELOG.md](../../CHANGELOG.md) (English) and [CHANGELOG.ru.md](../../CHANGELOG.ru.md) (Russian); release notes
are built from both.

**Releasing a 1.x version.** On the `1.x` branch: bump the version in `__init__.py`, add a section to both
changelogs, then Actions → Release 1.x → Run workflow on `1.x` with "publish" checked. The [Release](../../.github/workflows/release.yml)
workflow runs the tests on a clean Windows runner, downloads the vendor database, builds the portable exe and the
installer, checks the built exe (start-up, scan, PDF and Excel export) and publishes release `v<version>` with notes
taken from the changelogs. The tag is created on the built commit. A tag pushed from the console also works
(`git tag v1.0.1 && git push origin v1.0.1`); it must match the version in `__init__.py`. Without "publish" you only
get a build, with files in the run artifacts. With "draft" on a `release/<version>` branch the workflow publishes a
draft pre-release for testing on a laptop; publishing the same version removes the draft.

**Locally on Windows.** Requires Python 3 and Inno Setup 6.3+ (https://jrsoftware.org/isdl.php):

    build_installer.bat      installer: dist\installer\WiFiBeaconScanner-Setup-<version>.exe
    build.bat                portable exe: dist\WiFiBeaconScanner.exe

PyInstaller builds the app into a folder (`--onedir`, no console, with an icon and version info in the file
properties), and Inno Setup packs it using `installer\WiFiBeaconScanner.iss`. If `wifi_beacon_scanner\data\manuf`
exists, the vendor database is bundled.

Antivirus software sometimes flags PyInstaller builds (false positive). The folder build (installer) triggers this
less often than the single-file exe.

**Tests:**

    python -m unittest discover -s tests

[CI](../../.github/workflows/ci.yml) runs them on Windows and Linux on every push and pull request. On Windows it
also prints a PDF with the real Edge, opens the app window with a clean Edge profile and checks that the app exits
when the window is closed, and calls the Windows APIs used by sessions and the event log.

### Layout (1.x)

    wifi_beacon_scanner/ie.py          IE parsing (RSN, HT/VHT/HE/EHT, QBSS Load, Extended Capabilities, ...)
    wifi_beacon_scanner/model.py       Bss and Snapshot (JSON)
    wifi_beacon_scanner/amend.py       802.11 amendments (d/e/h/i/k/r/u/v/w etc.) from Capability and IEs
    wifi_beacon_scanner/rules.py       diagnostic rules
    wifi_beacon_scanner/report.py      HTML / CSV / console
    wifi_beacon_scanner/oui.py         vendor by BSSID (manuf)
    wifi_beacon_scanner/scanner_win.py wlanapi.dll via ctypes (Windows only)
    wifi_beacon_scanner/backends.py    data sources: Windows and demo
    wifi_beacon_scanner/diff.py        comparison of two snapshots (before/after)
    wifi_beacon_scanner/conn.py        connection journal: roams, disconnects, ping-pong, sticky client
    wifi_beacon_scanner/conn_win.py    connection polling and WLAN notifications (Windows only)
    wifi_beacon_scanner/winstructs.py  Native Wifi API structures for ctypes
    wifi_beacon_scanner/survey.py      floor plan survey (points, project)
    wifi_beacon_scanner/session.py     state machine: connection and roaming sessions
    wifi_beacon_scanner/onex.py        802.1X (ONEX) notification parsing
    wifi_beacon_scanner/ip_win.py      IPv4 and DHCP lease (GetAdaptersInfo)
    wifi_beacon_scanner/winlog*.py     WLAN-AutoConfig event log (wevtapi)
    wifi_beacon_scanner/mcs.py         MCS and PHY rates for 802.11n/ac/ax, MCS estimate from rate
    wifi_beacon_scanner/xlsx.py        .xlsx writer without libraries
    wifi_beacon_scanner/pdf.py         PDF via headless Edge/Chromium
    wifi_beacon_scanner/applog.py      app log file (logs\app.log)
    wifi_beacon_scanner/update.py      new version check on GitHub Releases (on demand)
    wifi_beacon_scanner/synth.py       synthetic IEs built from the spec (tests and demo)
    wifi_beacon_scanner/i18n*.py       interface language: tr()/N_() and the English catalog
    wifi_beacon_scanner/web/           server (stdlib) and UI (HTML/CSS/JS without external libraries)
    run_gui.py               entry point for the exe
    installer/               Inno Setup script and exe version file
    assets/                  icon
    build.bat, build_installer.bat     building the exe and the installer
    .github/workflows/                 CI (tests) and Release (exe, installer, GitHub Release)
    tools/smoke_exe.py                 checks the built exe in Release: start-up, scan, PDF and Excel export
    tools/smoke_window.py              CI: app window with a clean Edge profile, exit on close
    tools/smoke_winapi.py              CI: GetAdaptersInfo and event log reading on a real Windows
    tools/release_notes.py             release notes from CHANGELOG.md and CHANGELOG.ru.md
    tools/i18n_scan.py                 untranslated strings in Python and the page
    tools/run_tests.py                 tests in CI: failures shown as annotations
    tests/                   unittest
