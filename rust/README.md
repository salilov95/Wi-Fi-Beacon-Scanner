# Wi-Fi Beacon Scanner 2.x (Rust + Tauri 2) — work in progress

**English** · [Русский](README.ru.md)

The next version of the program: its own window instead of a local server plus an Edge window, one small exe,
then Linux and macOS. The working version is still **1.x in Python** (the repository root); this folder does not
touch it, has its own workflow (`.github/workflows/rust.yml`), and 2.x builds are published only as
`v2.0.0-alpha.N` pre-releases.

## What is here

| Crate | What | Status |
|---|---|---|
| `crates/wbs-core` | beacon (IE) parsing, BSS model, security, MCS, IE tree for the Beacon tab, 802.11 amendments, problems, channel quality and utilisation, translations; the connection journal and sessions; program state and its `/api/*` (history, before/after comparison, settings, CSV/JSON export); scanning through wlanapi.dll (Windows) | matches 1.x on every golden file in full (4 scans × 2 languages); `/api/state` and exports match the Python version (`tools/compare_state.py`) |
| `app` | Tauri 2 window: the same UI as 1.x served through its own `wbs` protocol (no port, no local server); NSIS installer | 2.0.0-alpha.2, built in CI on Windows |

Not ported yet (2.0 alpha answers with a clear message): the Windows event log, the survey, HTML/PDF/Excel reports,
the update check, the demo mode. 2.x installs next to 1.x: its own identifier, install folder,
settings (`%APPDATA%\WiFiBeaconScanner2`) and log; 1.x settings are read once while 2.x has none of its own.

## How it is checked

The core reads the same scans as the Python version (`contract/fixtures`) and compares its output with that
version's expected output (`contract/golden`) — `crates/wbs-core/tests/contract.rs`. Contract rules:
[`contract/README.md`](../contract/README.md).

    cd rust
    cargo test          # unit tests and the golden comparison
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

Requires Rust (`rustup`, stable channel; CI pins 1.97.0). `wbs-core` has no external dependencies and builds
without access to crates.io.

The UI with the Rust API, without Tauri, in any browser (data from a scan file):

    cargo run --example devserver -- ../contract/fixtures/demo-office.json 8765
    python ../tools/compare_state.py target/debug/examples/devserver     # compare with 1.x

The `win` module (wlanapi) builds only on Windows; to check it on Linux:
`RUSTFLAGS="--cfg wbs_check_win" cargo clippy`.

The window (`app`) is a separate workspace that needs crates.io; CI builds it (`.github/workflows/rust.yml`, job `app`):

    cd app
    npx @tauri-apps/cli@2 build        # exe and NSIS installer in target/release
