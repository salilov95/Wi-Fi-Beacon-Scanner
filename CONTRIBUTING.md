# Contributing

**English** · [Русский](CONTRIBUTING.ru.md)

1. Branch off `main`: `feature/<what>` or `fix/<what>`.
2. No external dependencies in the app: it must run on a clean Windows with just Python and build into an exe.
   Tests may use `requirements-dev.txt`.
3. Tests: `python -m unittest discover -s tests`. New logic comes with a test; IE parsing is tested on bytes built
   from the standard (`wifi_beacon_scanner/synth.py`), not on the parser's own output.
4. Check the UI on demo data: `python -m wifi_beacon_scanner gui --demo`.
5. Describe the change in [CHANGELOG.md](CHANGELOG.md) ("Unreleased") and [CHANGELOG.ru.md](CHANGELOG.ru.md)
   ("Не выпущено"). Documentation is bilingual: `README.md` / `README.ru.md`, `docs/en/` / `docs/ru/`.
6. Commit messages: first line in the imperative mood, up to ~70 characters (`Fix PDF export on Windows`),
   then what and why.
7. Pull request into `main`; CI must be green.

Releasing a version is described in [docs/en/development.md](docs/en/development.md#build).
