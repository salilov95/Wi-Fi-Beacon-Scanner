# Разработка, сборка и выпуск

[← README](../README.md)

## Запуск из исходников

Нужен Python 3.8+ для Windows, внешних зависимостей нет.

    python -m wifi_beacon_scanner gui --ssid ИМЯ_СЕТИ     # окно
    python -m wifi_beacon_scanner gui --demo              # демо-данные, работает и не на Windows
    pip install .  &&  wifi-beacon-scanner gui            # как пакет

## Командная строка: первый запуск по шагам

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

## Сборка

Версия задаётся в одном месте: `wifi_beacon_scanner/__init__.py`. Изменения описываются в [CHANGELOG.md](../CHANGELOG.md).

**Выпуск версии (основной путь).** Поднять версию в `__init__.py`, дописать раздел в CHANGELOG, закоммитить
в `main`, затем Actions → Release → Run workflow с галочкой «publish». Workflow [Release](../.github/workflows/release.yml)
на чистом Windows прогонит тесты, скачает базу вендоров, соберёт переносной exe и установщик, проверит
собранный exe (запуск, скан, выгрузка PDF и Excel) и опубликует релиз `v<версия>` с текстом из CHANGELOG.
Тег создаётся на собранном коммите. Можно и тегом из консоли (`git tag v0.7.0 && git push origin v0.7.0`),
тег должен совпадать с версией в `__init__.py`. Без галочки получится только сборка, файлы будут в артефакте запуска.

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

[CI](../.github/workflows/ci.yml) гоняет их на Windows и Linux при каждом push и pull request.

## Структура

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
    wifi_beacon_scanner/mcs.py         MCS и PHY-скорости 802.11n/ac/ax, оценка MCS по скорости
    wifi_beacon_scanner/xlsx.py        запись .xlsx без библиотек
    wifi_beacon_scanner/pdf.py         PDF через Edge/Chromium headless
    wifi_beacon_scanner/synth.py       сборка синтетических IE по спецификации (тесты и демо)
    wifi_beacon_scanner/web/           сервер (stdlib) и интерфейс (HTML/CSS/JS без внешних библиотек)
    run_gui.py               точка входа для exe
    installer/               сценарий Inno Setup и файл версии для exe
    assets/                  иконка
    build.bat, build_installer.bat     сборка exe и установщика
    .github/workflows/                 CI (тесты) и Release (сборка exe, установщик, GitHub Release)
    tools/smoke_exe.py                 проверка собранного exe в Release: запуск, скан, выгрузка PDF и Excel
    tools/release_notes.py             текст релиза из CHANGELOG.md
    tools/run_tests.py                 тесты в CI: упавшие видны аннотациями
    tests/                   unittest
