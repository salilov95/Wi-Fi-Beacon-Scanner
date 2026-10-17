[English](CONTRIBUTING.md) · **Русский**

# Как вносить изменения

1. Ветка от `main`: `feature/<что-делаем>` или `fix/<что-чиним>`.
2. Программа - версия 2 в `rust/`: `wbs-core` без внешних крейтов (собирается и тестируется где угодно),
   `rust/app` - окно на Tauri 2. Интерфейс - `wifi_beacon_scanner/web/static`, общий с 1.x.
3. Тесты: `cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` и
   `python tools/run_tests.py` (1.x и контракт). Изменение результатов разбора - это изменение эталонов
   (`contract/`, см. [contract/README.ru.md](contract/README.ru.md)) и запись в истории изменений. Новая логика - с
   тестом; разбор IE проверяется на байтах, собранных по стандарту, а не на выводе самого парсера.
4. Интерфейс смотреть на демо-данных: в `rust/` запустить `cargo run --example devserver -- ../contract/fixtures/demo-base.json 8765`
   с `WBS_BACKEND=demo` и открыть `http://127.0.0.1:8765/`.
5. Изменения описать в [CHANGELOG.md](CHANGELOG.md) (раздел «Unreleased») и [CHANGELOG.ru.md](CHANGELOG.ru.md)
   (раздел «Не выпущено»). Документация - на двух языках: `README.md` / `README.ru.md`, `docs/en/` / `docs/ru/`.
6. Сообщения коммитов: первая строка в повелительном наклонении до ~70 символов
   (`Fix PDF export on Windows`), дальше - что и почему.
7. Pull request в `main`; CI должен быть зелёным.

Выпуск версии описан в [docs/ru/development.md](docs/ru/development.md#выпуск-версии).
