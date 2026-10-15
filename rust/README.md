# Wi-Fi Beacon Scanner 2.x (Rust + Tauri 2) — work in progress

**English** · [Русский](README.ru.md)

The next version of the program: its own window instead of a local server plus an Edge window, one small exe,
then Linux and macOS. The working version is still **1.x in Python** (the repository root); this folder does not
touch it, has its own workflow (`.github/workflows/rust.yml`), and 2.x builds are published only as
`v2.0.0-alpha.N` pre-releases.

## What is here

| Crate | What | Status |
|---|---|---|
| `crates/wbs-core` | beacon (IE) parsing, BSS model, security, MCS and PHY rate, network table row | 37 row fields match 1.x on every golden file |

Not ported yet: 802.11 amendment notes and the IE tree for the Beacon tab (need the translation catalogue),
problems, channel quality and utilisation, the Tauri window, wlanapi scanning, the connection journal, reports.

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
