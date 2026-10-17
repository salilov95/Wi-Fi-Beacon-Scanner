# Разработка, сборка и выпуск

[← README](../../README.ru.md) · [English](../en/development.md)

## Версия 2 (Rust + Tauri 2)

Программа - в `rust/`:

    rust/crates/wbs-core/        всё, кроме окна, без внешних крейтов (собирается и тестируется на любой ОС)
      src/ie.rs model.rs mcs.rs describe.rs amend.rs rules.rs row.rs   разбор beacon и анализ
      src/conn.rs session.rs onex.rs                                   журнал подключения, сессии, 802.1X
      src/report.rs xlsx.rs zip.rs pdf.rs                              отчёты HTML/CSV/JSON/Excel, PDF через Edge
      src/survey.rs demo.rs diff.rs prefs.rs                           обход, демо-режим, сравнение, настройки вида
      src/i18n.rs json.rs xml.rs update.rs clock.rs oui.rs             языки, JSON/XML, обновления, время, вендоры
      src/app.rs                                                       состояние и маршруты /api/* окна
      src/win.rs win_conn.rs win_log.rs                                Windows: wlanapi, уведомления, iphlpapi, wevtapi, WinHTTP
      examples/devserver.rs                                            тот же API по HTTP (тесты, скриншоты)
      tests/                                                           API, эталоны, сценарии журнала
    rust/app/                    окно Tauri 2: main.rs, build.rs (зашивает базу вендоров), tauri.conf.json
    wifi_beacon_scanner/web/static/   интерфейс, общий с 1.x, зашит в exe
    contract/                    эталоны: что обе версии выдают на фиксированных сканах
    tools/compare_state.py       API 2.x против 1.x: состояние, выгрузки, отчёты, обход, настройки
    tools/screenshots.py         скриншоты README с devserver в демо-режиме

Окно открывает `http://wbs.localhost/`, и это не сетевой адрес: каждый запрос страницы Tauri отдаёт программе через
свой протокол `wbs`, а `wbs_core::app::App::handle` отвечает тем же JSON, что сервер 1.x. Поэтому совпадение с 1.x
проверяется сравнением ответов API (`tools/compare_state.py`).

### Сборка и тесты

Ядро собирается где угодно, где есть Rust (stable; CI берёт версию, закреплённую в `.github/workflows/rust.yml`):

    cd rust
    cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
    RUSTFLAGS="--cfg wbs_check_win" cargo clippy --target-dir target/wincheck --all-targets   # модули Windows, на Linux
    cargo build --example devserver && python ../tools/compare_state.py target/debug/examples/devserver

Окно и установщик собираются на Windows, нужны Rust и Node.js:

    cd rust/app
    npx @tauri-apps/cli@2 build      # target/release/wbs-app.exe и target/release/bundle/nsis/*-setup.exe

С `WBS_MANUF=<путь к файлу manuf из Wireshark>` база вендоров зашивается в exe.

Демо без Wi-Fi: `WiFiBeaconScanner2.exe --demo` или devserver на любой ОС:
`WBS_BACKEND=demo cargo run --example devserver -- ../contract/fixtures/demo-base.json 8765`, затем
`http://127.0.0.1:8765/`.

### Выпуск версии

1. Поднять версию в `rust/app/tauri.conf.json`, `rust/app/Cargo.toml` и `rust/crates/wbs-core/Cargo.toml`;
   дописать раздел в [CHANGELOG.md](../../CHANGELOG.md) и [CHANGELOG.ru.md](../../CHANGELOG.ru.md).
2. Pull request в `main`. Workflow [Rust](../../.github/workflows/rust.yml) прогоняет проверки на Windows и Linux,
   собирает окно и установщик, запускает exe, тихо ставит и удаляет его и выкладывает черновой pre-release с файлами
   для проверки.
3. После слияния: Actions → Rust → Run workflow на `main` с галочкой «publish». Workflow ещё раз собирает и проверяет
   и публикует релиз `v<версия>` с текстом из обоих CHANGELOG; тег создаётся на собранном коммите. Версия с дефисом
   (`2.1.0-rc.1`) публикуется как pre-release и «последней» не становится.
4. Исправления 1.x: ветка `1.x`, версия в `wifi_beacon_scanner/__init__.py`, затем тег `v1.x.y` или Actions →
   Release 1.x на этой ветке. Такой релиз «последним» не становится.

`tools/screenshots.py` (Playwright и Pillow, нужны только ему) переснимает скриншоты README в тёмной теме:
`docs/images` (русские) и `docs/images/en`.

## Переводы

Исходный язык - русский, и русская строка сама служит ключом перевода.

- Python: видимый пользователю текст идёт через `tr("…")` (`wifi_beacon_scanner/i18n.py`); строки в таблицах
  уровня модуля помечаются `N_("…")` и проходят через `tr()` там, где показываются. Подстановка - после
  перевода: `tr("слабый сигнал %d дБм") % rssi`. Переводы - в `wifi_beacon_scanner/i18n_en.py`, с теми же
  `%s`/`%d` в том же порядке.
- Страница: `T('…', {name: value})` в `app.js`, переводы - в `web/static/i18n.js`; статический текст
  `index.html` переводится при загрузке. Смена языка перезагружает страницу.
- `python tools/i18n_scan.py missing` и `python tools/i18n_scan.py js` показывают строки без перевода,
  `report` - кириллицу вне `tr()`. `tests/test_i18n.py` падает, если перевода нет или в нём потерялась подстановка.

## Версия 1.x (Python): эталонная реализация

Версия 1.x остаётся в репозитории: по `wifi_beacon_scanner/` строятся эталоны `contract/`, а в ветке `1.x`
выпускаются исправления 1.x. Ниже - как её запускать и собирать.

### Запуск из исходников

Нужен Python 3.8+ для Windows, внешних зависимостей нет.

    python -m wifi_beacon_scanner gui --ssid ИМЯ_СЕТИ     # окно
    python -m wifi_beacon_scanner gui --demo              # демо-данные, работает и не на Windows
    pip install .  &&  wifi-beacon-scanner gui            # как пакет

### Командная строка: первый запуск по шагам

**1. Проверь, что тесты проходят на твоей машине**

    python -m unittest discover -s tests

Ожидается `OK` в конце (часть тестов пропускается, если нет Chromium или LibreOffice). Зачем: так ты убеждаешься, что парсер работает одинаково
у тебя и у меня, до того как доверять результатам скана.

**2. Проверь, что адаптер виден**

    python -m wifi_beacon_scanner interfaces

Ожидается строка вида `0: Intel(R) Wi-Fi 6 AX201 ...`. Если пусто или ошибка - сканировать
нечем, дальше идти нет смысла.

**3. Первый скан, только сохранить сырые данные**

    python -m wifi_beacon_scanner scan --save snap.json

Зачем сначала `--save`: снапшот содержит сырые байты IE, по нему можно воспроизвести разбор
на любой ОС и найти ошибки парсера на реальных данных. Если в выводе `BSS в эфире: 0`,
а сети рядом точно есть - см. «Известные ограничения».

**4. Нормальный отчёт по «своей» сети**

    python -m wifi_beacon_scanner scan --ssid ИМЯ_СЕТИ --html report.html --csv bss.csv --save snap.json

Открой `report.html`. Флаг `--ssid` можно указывать несколько раз: проблемы конфигурации и
слабого сигнала считаются только для этих сетей, чужие учитываются как помеха на канале.

**5. Разбор снапшота без сканирования (на любой ОС)**

    python -m wifi_beacon_scanner analyze snap.json --ssid ИМЯ_СЕТИ --html report.html

### Сборка (1.x)

Версия задаётся в одном месте: `wifi_beacon_scanner/__init__.py`. Изменения описываются на двух языках:
[CHANGELOG.md](../../CHANGELOG.md) (английский) и [CHANGELOG.ru.md](../../CHANGELOG.ru.md); текст релиза собирается из обоих.

**Выпуск версии 1.x.** В ветке `1.x`: поднять версию в `__init__.py`, дописать раздел в CHANGELOG, затем
Actions → Release 1.x → Run workflow на `1.x` с галочкой «publish». Workflow [Release](../../.github/workflows/release.yml)
на чистом Windows прогонит тесты, скачает базу вендоров, соберёт переносной exe и установщик, проверит
собранный exe (запуск, скан, выгрузка PDF и Excel) и опубликует релиз `v<версия>` с текстом из CHANGELOG.
Тег создаётся на собранном коммите. Можно и тегом из консоли (`git tag v0.7.0 && git push origin v0.7.0`),
тег должен совпадать с версией в `__init__.py`. Без галочки получится только сборка, файлы будут в артефакте запуска.
С галочкой «draft» на ветке `release/<версия>` workflow выкладывает черновой pre-release для проверки на ноутбуке;
при публикации той же версии черновик удаляется.

**Локально на Windows.** Нужны Python 3 и Inno Setup 6.3+ (https://jrsoftware.org/isdl.php):

    build_installer.bat      установщик: dist\installer\WiFiBeaconScanner-Setup-<версия>.exe
    build.bat                переносной exe: dist\WiFiBeaconScanner.exe

PyInstaller собирает программу в папку (`--onedir`, без консоли, с иконкой и версией в свойствах файла),
Inno Setup упаковывает её по сценарию `installer\WiFiBeaconScanner.iss`. Если есть `wifi_beacon_scanner\data\manuf`,
база вендоров вкладывается в сборку.

Антивирусы иногда ругаются на PyInstaller-сборки (ложное срабатывание). Сборка в папку (установщик)
вызывает это реже, чем однофайловый exe.

**Тесты:**

    python -m unittest discover -s tests

[CI](../../.github/workflows/ci.yml) гоняет их на Windows и Linux при каждом push и pull request. На Windows ещё
печатает PDF настоящим Edge, открывает окно программы с чистым профилем Edge и проверяет выход при закрытии,
вызывает Windows API, на которых держатся сессии и журнал Windows.

### Структура (1.x)

    wifi_beacon_scanner/ie.py          разбор IE (RSN, 11k/r/v, HT/VHT/HE, QBSS Load, ...)
    wifi_beacon_scanner/model.py       Bss и Snapshot (JSON)
    wifi_beacon_scanner/rules.py       правила диагностики
    wifi_beacon_scanner/report.py      HTML / CSV / консоль
    wifi_beacon_scanner/oui.py         вендор по BSSID (manuf)
    wifi_beacon_scanner/scanner_win.py wlanapi.dll через ctypes (только Windows)
    wifi_beacon_scanner/backends.py    источники данных: Windows и демо
    wifi_beacon_scanner/diff.py        сравнение двух снапшотов (до/после)
    wifi_beacon_scanner/conn.py        журнал подключения: роуминги, обрывы, пинг-понг, залипание
    wifi_beacon_scanner/conn_win.py    опрос подключения и уведомления WLAN (только Windows)
    wifi_beacon_scanner/winstructs.py  структуры Native Wifi API для ctypes
    wifi_beacon_scanner/survey.py      обход по плану этажа (точки, проект)
    wifi_beacon_scanner/session.py     машина состояний: сессии подключения и роуминга
    wifi_beacon_scanner/onex.py        разбор уведомлений 802.1X (ONEX)
    wifi_beacon_scanner/ip_win.py      IPv4 и аренда DHCP (GetAdaptersInfo)
    wifi_beacon_scanner/winlog*.py     журнал WLAN-AutoConfig (wevtapi)
    wifi_beacon_scanner/amend.py       дополнения 802.11 (d/e/h/i/k/r/u/v/w и др.) по Capability и IE
    wifi_beacon_scanner/applog.py      журнал программы в файл (logs\app.log)
    wifi_beacon_scanner/update.py      проверка новой версии на GitHub Releases (по кнопке)
    wifi_beacon_scanner/mcs.py         MCS и PHY-скорости 802.11n/ac/ax, оценка MCS по скорости
    wifi_beacon_scanner/xlsx.py        запись .xlsx без библиотек
    wifi_beacon_scanner/pdf.py         PDF через Edge/Chromium headless
    wifi_beacon_scanner/synth.py       сборка синтетических IE по спецификации (тесты и демо)
    wifi_beacon_scanner/i18n*.py       язык интерфейса: tr()/N_() и английский каталог
    wifi_beacon_scanner/web/           сервер (stdlib) и интерфейс (HTML/CSS/JS без внешних библиотек)
    run_gui.py               точка входа для exe
    installer/               сценарий Inno Setup и файл версии для exe
    assets/                  иконка
    build.bat, build_installer.bat     сборка exe и установщика
    .github/workflows/                 CI (тесты) и Release (сборка exe, установщик, GitHub Release)
    tools/smoke_exe.py                 проверка собранного exe в Release: запуск, скан, выгрузка PDF и Excel
    tools/smoke_window.py              CI: окно программы с чистым профилем Edge, выход при закрытии
    tools/smoke_winapi.py              CI: GetAdaptersInfo и чтение журнала на настоящей Windows
    tools/release_notes.py             текст релиза из CHANGELOG.md и CHANGELOG.ru.md
    tools/i18n_scan.py                 строки без перевода в Python и на странице
    tools/run_tests.py                 тесты в CI: упавшие видны аннотациями
    tests/                   unittest
