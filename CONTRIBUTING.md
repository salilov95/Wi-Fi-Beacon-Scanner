# Contributing

**English** · [Русский](CONTRIBUTING.ru.md)

1. Branch off `main`: `feature/<what>` or `fix/<what>`.
2. The app is version 2 in `rust/`: `wbs-core` has no external crates (it builds and is tested anywhere),
   `rust/app` is the Tauri 2 window. The UI is `wifi_beacon_scanner/web/static`, shared with 1.x.
3. Tests: `cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`, plus
   `python tools/run_tests.py` (1.x and the contract). A change of analysis results is a change of the golden files
   (`contract/`, see [contract/README.md](contract/README.md)) and goes into the changelog. New logic comes with a
   test; IE parsing is tested on bytes built from the standard, not on the parser's own output.
4. Check the UI on demo data: `cargo run --example devserver -- ../contract/fixtures/demo-base.json 8765` in `rust/`
   with `WBS_BACKEND=demo`, then open `http://127.0.0.1:8765/`.
5. Describe the change in [CHANGELOG.md](CHANGELOG.md) ("Unreleased") and [CHANGELOG.ru.md](CHANGELOG.ru.md)
   ("Не выпущено"). Documentation is bilingual: `README.md` / `README.ru.md`, `docs/en/` / `docs/ru/`.
6. Commit messages: first line in the imperative mood, up to ~70 characters (`Fix PDF export on Windows`),
   then what and why.
7. Pull request into `main`; CI must be green.

Releasing a version is described in [docs/en/development.md](docs/en/development.md#releasing-a-version).
