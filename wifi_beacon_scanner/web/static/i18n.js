'use strict';
// Язык интерфейса. Ключ - русская строка из app.js / index.html, значение - перевод.
// Язык страницы задаёт программа (<html lang="..">) из «Вид» → «Язык» или языка Windows;
// при переключении страница перезагружается, поэтому язык во время работы не меняется.
// Строки с подстановкой: T('показано {a} из {b}', {a: 3, b: 5}).
const LANG = document.documentElement.lang === 'en' ? 'en' : 'ru';
const LOC = LANG === 'en' ? 'en-GB' : 'ru-RU';

const I18N_EN = {
  // ---- index.html ----
  'Адаптер': 'Adapter', 'Сканировать': 'Scan', 'Авто': 'Auto', 'Интервал автоскана': 'Auto-scan interval',
  '5 с': '5 s', '10 с': '10 s', '30 с': '30 s', '60 с': '60 s', 'Мои SSID': 'My SSIDs', 'Открыть снапшот': 'Open snapshot',
  'Экспорт ▾': 'Export ▾', 'Какие сети включить': 'Which networks to include', 'Как в таблице сейчас': 'As shown in the table',
  'Только мои SSID': 'My SSIDs only', 'Все сети': 'All networks', 'Формат': 'Format', 'Отчёт (PDF)': 'Report (PDF)',
  'Отчёт (Excel)': 'Report (Excel)', 'Отчёт (HTML)': 'Report (HTML)', 'Таблица (CSV)': 'Table (CSV)',
  'История замеров (CSV)': 'Measurement history (CSV)', 'Снапшот (JSON)': 'Snapshot (JSON)',
  'Журнал подключения (CSV)': 'Connection journal (CSV)', 'Сессии подключения (CSV)': 'Connection sessions (CSV)',
  'Вид ▾': 'View ▾', 'Тема': 'Theme', 'Строки таблицы': 'Table rows', 'Обычные': 'Normal', 'Плотные': 'Compact',
  'Колонки': 'Columns', 'Сбросить ширину столбцов': 'Reset column widths', 'Клавиши': 'Keys', 'сканировать': 'scan',
  'поиск по таблице': 'search the table', 'вкладки': 'tabs', 'строки таблицы': 'table rows',
  'сбросить поиск и подсветку': 'clear search and highlight', 'граница заголовка': 'header border',
  'потянуть - ширина столбца, двойной щелчок - по содержимому': 'drag - column width, double-click - fit to content',
  'О программе': 'About', 'Папка с журналом': 'Log folder', 'Проверить обновления': 'Check for updates', 'Выход': 'Quit',
  'Язык': 'Language', 'Русский': 'Русский', 'Сводка': 'Summary', '6 ГГц': '6 GHz', 'Минимальный сигнал': 'Minimum signal', 'Любой сигнал': 'Any signal',
  'от −67 дБм': 'from −67 dBm', 'от −75 дБм': 'from −75 dBm', 'от −85 дБм': 'from −85 dBm', 'Любая защита': 'Any security',
  'Открытые': 'Open', 'Устаревшие (WEP, WPA1, TKIP)': 'Legacy (WEP, WPA1, TKIP)', 'WPA3 и OWE': 'WPA3 and OWE',
  'Дополнения 802.11 из beacon': '802.11 amendments from beacons', 'есть все отмеченные': 'has all selected',
  'нет ни одного из отмеченных': 'has none of the selected', 'Поиск: SSID, BSSID, вендор': 'Search: SSID, BSSID, vendor',
  'По SSID': 'By SSID', 'Только мои': 'Mine only', 'Потяни, чтобы изменить высоту': 'Drag to change the height',
  'Каналы': 'Channels', 'Обзор': 'Overview', 'Утилизация': 'Utilization', 'Сигнал во времени': 'Signal over time',
  'Сессии': 'Sessions', 'Журнал Windows': 'Windows log', 'Сравнение': 'Compare', 'Развернуть': 'Expand', 'Свернуть': 'Collapse',

  // ---- темы, шкала сигнала ----
  'Как в системе': 'System', 'Светлая': 'Light', 'Тёмная': 'Dark', 'Тёплая бумага': 'Warm paper', 'Контрастная': 'High contrast',
  'отлично': 'excellent', 'хорошо': 'good', 'рабочий': 'usable', 'слабый': 'weak', 'плохо': 'poor', 'на грани': 'marginal',
  'дБм': 'dBm', 'ГГц': 'GHz', 'МГц': 'MHz', 'Мбит/с': 'Mbit/s', 'с': 's', 'мс': 'ms', 'мин': 'min', 'ч': 'h', 'байт': 'bytes',
  'слабее': 'weaker', 'сильнее': 'stronger', 'да': 'yes', 'нет': 'no', 'без': 'without', 'из': 'of',

  // ---- таблица ----
  '802.11d - код страны': '802.11d - country code', 'дополнения не объявлены': 'no amendments advertised',
  'Вендор': 'Vendor', 'Канал': 'Channel', 'Ширина': 'Width', 'RSSI, дБм': 'RSSI, dBm', 'Тренд': 'Trend',
  'RSSI мин / ср / макс': 'RSSI min / avg / max', 'Виден, %': 'Seen, %', 'Безопасность': 'Security', 'Шифры': 'Ciphers',
  'Потоки': 'Streams', 'Макс. MCS': 'Max MCS', 'Макс. PHY, Мбит/с': 'Max PHY, Mbit/s', 'Загрузка': 'Load', 'Станций': 'Stations',
  'Страна': 'Country', 'Качество, %': 'Quality, %', 'К этой BSS сейчас подключён ноутбук': 'The laptop is connected to this BSS',
  'подключён': 'connected', 'скрыт': 'hidden', 'Локально администрируемый MAC': 'Locally administered MAC',
  'legacy, до {r} Мбит/с': 'legacy, up to {r} Mbit/s',
  '{phy}: MCS 0–{mcs}, потоков {nss}, {w} МГц → до {r} Мбит/с (потолок PHY по beacon, не текущая скорость)':
    '{phy}: MCS 0–{mcs}, {nss} streams, {w} MHz → up to {r} Mbit/s (PHY ceiling from the beacon, not the current rate)',
  'за {n} сканов: от {a} до {b} дБм': 'over {n} scans: {a} to {b} dBm',
  'Потяни - ширина столбца, двойной щелчок - по содержимому': 'Drag to resize the column, double-click to fit the content',
  'BSS: {n}, диапазоны: {b} ГГц, лучший сигнал {s} дБм': 'BSS: {n}, bands: {b} GHz, best signal {s} dBm',
  'показано {a} из {b}': 'showing {a} of {b}', 'Подключаюсь к программе…': 'Connecting to the app…',
  'Идёт сканирование…': 'Scanning…', 'Скан не удался, подробности - в плашке сверху.': 'The scan failed, see the banner above.',
  'Автоскан повторит попытку.': 'Auto-scan will retry.', 'Windows вернула пустой список сетей.': 'Windows returned an empty network list.',
  'Автоскан повторит скан через несколько секунд.': 'Auto-scan will try again in a few seconds.', 'Нажми «Сканировать».': 'Click "Scan".',
  'Данных пока нет. Нажми «Сканировать».': 'No data yet. Click "Scan".',
  'Под фильтры ничего не попало. Ослабь фильтры: сигнал, защита, 802.11.': 'Nothing matches the filters. Relax them: signal, security, 802.11.',

  // ---- полоса сводки, каналы ----
  'Сводка появится после первого скана.': 'The summary appears after the first scan.', 'Лучший сигнал': 'Best signal',
  'Макс. загрузка': 'Max load', 'канал {c}': 'channel {c}', 'кан. {c}': 'ch. {c}', 'канал': 'channel',
  'Открыть проблемы': 'Open problems', 'Проблемы': 'Problems', 'радио {r} (BSS {n})': '{r} radios ({n} BSS)', 'загрузка {u}%': 'load {u}%',
  'соседей не слышно': 'no neighbors heard', 'лучший': 'best', 'занят': 'busy', 'Свободность каналов, {b} ГГц': 'Channel ranking, {b} GHz',
  'Ниже дБм, значит свободнее (сумма сигналов соседей на канале). Каналы с загрузкой от 50% идут последними. Учитывается вся полоса соседа: точка 80 МГц занимает четыре канала. Несколько SSID одного радио считаются одним передатчиком. Оценка верна для места, где стоит ноутбук.':
    'Lower dBm means freer (sum of neighbor signals on the channel). Channels with 50% load or more come last. A neighbor\'s whole bandwidth counts: an 80 MHz AP occupies four channels. Several SSIDs of one radio count as one transmitter. The ranking is valid where the laptop is.',
  'Высота показывает уровень сигнала, ширина — занимаемую полосу. Нажми на полосу, чтобы выбрать BSS.':
    'Height shows the signal level, width the occupied bandwidth. Click a shape to select the BSS.',
  'DFS, каналы 52–144': 'DFS, channels 52–144',

  // ---- сигнал во времени, обзор ----
  'Линии': 'Lines', 'Тепловая карта': 'Heat map', 'Как красить линии': 'How to color the lines', 'Цвет по уровню': 'Color by level',
  'Цвет по BSS': 'Color by BSS', 'Выбери строку в таблице: покажу уровень сигнала всех BSS этого SSID.': 'Select a row in the table to see the signal of every BSS of that SSID.',
  'выбранная BSS: мин {a}, среднее {b}, макс {c} дБм; видна в {p}% сканов': 'selected BSS: min {a}, avg {b}, max {c} dBm; seen in {p}% of scans',
  'Скачать историю (CSV)': 'Download history (CSV)', 'Нужно минимум два скана. Включи «Авто», и график начнёт заполняться.': 'At least two scans are needed. Turn on "Auto" and the chart will fill in.',
  'сейчас': 'now', '{n} с назад': '{n} s ago', 'нет данных': 'no data', ', из них мои {n}': ', mine {n}', ', макс. загрузка {u}%': ', max load {u}%',
  'мои SSID': 'my SSIDs', 'остальные': 'others', 'Число BSS по сканам': 'BSS count per scan', 'Нужно минимум два скана.': 'At least two scans are needed.',
  'за {n} сканов: от {a} до {b} BSS': 'over {n} scans: {a} to {b} BSS', 'сейчас {v}, минимум {a}, максимум {b} за {n} сканов': 'now {v}, min {a}, max {b} over {n} scans',
  'от −50 (отличный)': 'from −50 (excellent)', '−50…−60 (хороший)': '−50…−60 (good)', '−60…−67 (рабочий)': '−60…−67 (usable)',
  '−67…−75 (слабый)': '−67…−75 (weak)', '−75…−85 (плохой)': '−75…−85 (poor)', 'ниже −85 (на грани)': 'below −85 (marginal)',
  'локальный MAC': 'local MAC', 'неизвестен': 'unknown', 'BSS по каналам, {b} ГГц': 'BSS per channel, {b} GHz', 'Уровень сигнала, дБм': 'Signal level, dBm',
  'Защита': 'Security', 'Поколение Wi-Fi': 'Wi-Fi generation', 'Ширина канала': 'Channel width', 'Вендоры': 'Vendors',
  'все BSS': 'all BSSs', 'самые сильные BSS': 'strongest BSSs', 'BSS сети {s}': 'BSSs of {s}', ', показаны {a} из {b}': ', showing {a} of {b}',
  'Нужно минимум два скана. Включи «Авто», и карта начнёт заполняться.': 'At least two scans are needed. Turn on "Auto" and the map will fill in.',
  'сильнее, дБм. Пустая клетка: в этом скане BSS не слышна.': 'stronger, dBm. An empty cell means the BSS was not heard in that scan.',

  // ---- утилизация ----
  'загрузка по сканам': 'load per scan', 'за {n} сканов: от {a} до {b}%': 'over {n} scans: {a} to {b}%',
  'Источник — QBSS Load (IE 11) в beacon: доля времени, когда сама AP считает канал занятым. На канал берётся максимум среди AP, которые сообщают эту цифру. Нажми на строку, чтобы выбрать самую загруженную AP канала.':
    'Source: QBSS Load (IE 11) in beacons - the share of time the AP itself considers the channel busy. Per channel the maximum among the APs reporting it is used. Click a row to select the busiest AP of the channel.',
  'до 30% свободен, 30–50% умеренная, 50–70% высокая, от 70% перегружен': 'up to 30% free, 30–50% moderate, 50–70% high, 70% and above overloaded',
  'Ни одна AP в эфире не вещает QBSS Load, поэтому загрузку каналов по beacon узнать нельзя.': 'No AP on air advertises QBSS Load, so channel load cannot be determined from beacons.',
  'Каналов без данных: {n}.': 'Channels without data: {n}.', ' и ещё {n}': ' and {n} more',
  'канал {c}: максимум {a}%, среднее {b}% по {n} AP': 'channel {c}: max {a}%, average {b}% over {n} APs', 'мои': 'mine',
  'AP {a} из {b}, станций {s}: {top}': 'APs {a} of {b}, stations {s}: {top}', 'Нет данных QBSS Load (AP не вещают загрузку):': 'No QBSS Load data (APs do not advertise load):',
  '(не заданы)': '(not set)',

  // ---- журнал подключения ----
  'отключён': 'disconnected', 'отключается': 'disconnecting', 'ассоциация': 'association', 'аутентификация': 'authentication',
  'поиск сети': 'discovering', 'адаптер не готов': 'adapter not ready', 'неизвестно': 'unknown', 'подключение': 'connection',
  'обрыв': 'disconnect', 'роуминг': 'roam', 'смена сети': 'network change', 'пинг-понг': 'ping-pong', 'залипание': 'sticky client',
  'неудачное подключение': 'failed connection', 'отключение (Windows)': 'disconnect (Windows)',
  'Замеров пока мало: журнал пишется раз в секунду.': 'Not enough samples yet: the journal records once per second.',
  'без связи': 'no connection', 'полоса снизу - BSS:': 'bottom lane - BSS:', 'скорость не совпала ни с одним MCS': 'the rate does not match any MCS',
  ' или ещё {n} вар.': ' or {n} more', 'Журнал ещё не получил ни одного замера.': 'The journal has no samples yet.', 'Состояние': 'State',
  'Сеть': 'Network', 'профиль {p}': 'profile {p}', 'Сигнал': 'Signal', 'качество {q}%': 'quality {q}%', 'Скорость': 'Rate',
  'приём {rx} / передача {tx} Мбит/с': 'Rx {rx} / Tx {tx} Mbit/s', 'MCS по скорости (оценка)': 'MCS from rate (estimate)', 'приём': 'Rx', 'передача': 'Tx',
  'роумингов': 'roams', 'обрывов': 'disconnects', 'пинг-понгов': 'ping-pongs', 'залипаний': 'sticky', 'неудачных подключений': 'failed connections',
  'журнал с {t}': 'journal since {t}', 'все события': 'all events', 'только проблемы': 'problems only', 'Скачать журнал (CSV)': 'Download journal (CSV)',
  'Очистить': 'Clear', 'Причина:': 'Reason:', 'Время': 'Time', 'Событие': 'Event', 'Что произошло': 'What happened', 'Длит.': 'Duration',
  'Событий пока нет.': 'No events yet.', 'Время на каждой BSS': 'Time on each BSS', 'Сырые уведомления Windows ({n}) — для отладки': 'Raw Windows notifications ({n}) - for debugging',

  // ---- сессии ----
  'успешно': 'success', 'ошибка': 'error', 'прервано': 'aborted', 'идёт': 'in progress', 'начало подключения': 'connection start',
  'ассоциирован': 'associated', 'аутентификация (802.1X / 4-way)': 'authentication (802.1X / 4-way)', 'подключение завершено': 'connection complete',
  'начало роуминга': 'roam start', 'роуминг завершён': 'roam complete', 'разрыв ассоциации': 'disassociation', 'не удалось подключиться': 'connection failed',
  'аренда DHCP (DORA завершён)': 'DHCP lease (DORA complete)', '802.1X перезапущен': '802.1X restarted', 'стадии сессии': 'session stages',
  'аутентификация не завершилась': 'authentication did not complete', 'до IPv4': 'to IPv4', 'аутентификация (802.1X, 4-way handshake)': 'authentication (802.1X, 4-way handshake)',
  'до получения IPv4': 'until IPv4', 'Стадия': 'Stage', 'Подробности': 'Details', 'Итог': 'Result', 'Код причины': 'Reason code', 'учётка:': 'credentials:',
  'перезапусков: {n}': 'restarts: {n}', 'Причина 802.1X': '802.1X reason', 'Ошибка EAP': 'EAP error', 'DHCP-сервер {s}': 'DHCP server {s}',
  'Аренда получена': 'Lease obtained', 'подключений': 'connections', 'неудачных': 'failed', 'подключение, медиана': 'connection, median',
  'роуминг, медиана': 'roam, median', 'аутентификация, медиана': 'authentication, median', 'до IPv4, медиана': 'to IPv4, median',
  '802.1X успешно / отказ': '802.1X success / failure', 'все': 'all', 'подключения': 'connections', 'роуминги': 'roams', 'ошибки': 'errors',
  'Скачать сессии (CSV)': 'Download sessions (CSV)', 'Тип': 'Type', 'Точка': 'AP', 'Ассоц.': 'Assoc.', 'Аутент.': 'Auth.', 'Всего': 'Total',
  'До IPv4': 'To IPv4', 'Причина / IP': 'Reason / IP',
  'Сессий пока нет: они появятся при следующем подключении или роуминге ноутбука.': 'No sessions yet: they appear on the laptop\'s next connection or roam.',
  'Стадии - по уведомлениям Windows (ACM, MSM, 802.1X). «Аутентификация» включает обмен EAP и 4-way handshake: отдельно 4-way Windows не сообщает. «До IPv4» - от подключения до новой аренды DHCP (DORA) или появления адреса; если адрес остался с прошлого подключения, ожидания нет. Время роуминга считается от начала ассоциации с новой точкой.':
    'Stages come from Windows notifications (ACM, MSM, 802.1X). "Authentication" includes the EAP exchange and the 4-way handshake: Windows does not report the 4-way handshake separately. "To IPv4" is from connection to a new DHCP lease (DORA) or until the address appears; if the address was kept from the previous connection, there is no wait. Roam time is measured from the start of association with the new AP.',

  // ---- журнал Windows ----
  'безопасность / 4-way': 'security / 4-way', 'прочее': 'other', 'критично': 'critical', 'предупреждение': 'warning', 'информация': 'information', 'подробно': 'verbose',
  '24 ч': '24 h', '3 дня': '3 days', 'неделя': 'week', 'стадия': 'stage', 'все уровни': 'all levels', 'ошибки и предупреждения': 'errors and warnings',
  'Обновить': 'Refresh', 'Скачать (CSV)': 'Download (CSV)', 'обновлено {t}, дальше - раз в минуту': 'updated {t}, then every minute',
  'Читаю журнал Windows…': 'Reading the Windows log…', 'событий': 'events', 'подключений (8001)': 'connections (8001)',
  'не удалось подключиться (8002)': 'failed to connect (8002)', 'отключений (8003)': 'disconnects (8003)', 'ошибок 802.1X (12013)': '802.1X errors (12013)',
  'ошибок и предупреждений': 'errors and warnings', 'Частые причины': 'Most frequent reasons', 'За {p} событий под фильтр нет.': 'No events match the filter for {p}.',
  'За {p} событий нет.': 'No events for {p}.', 'нет полей': 'no fields', 'Уровень': 'Level', 'Сообщение Windows (нажми - поля события)': 'Windows message (click for event fields)',
  'Показаны первые 1000 из {n}; полный список - в CSV.': 'Showing the first 1000 of {n}; the full list is in the CSV.',
  'Журнал Microsoft-Windows-WLAN-AutoConfig/Operational: текст событий берётся из Windows на языке системы. Прав администратора не нужно.':
    'Microsoft-Windows-WLAN-AutoConfig/Operational log: event text comes from Windows in the system language. No administrator rights required.',
  'журнал не прочитан: {s}': 'log not read: {s}', 'ошибок за сутки: {n}': 'errors in the last day: {n}',
  'В журнале Windows рядом с этой сессией событий нет.': 'No Windows log events around this session.',
  'События журнала Windows рядом с сессией': 'Windows log events around the session', 'Сообщение Windows': 'Windows message',

  // ---- обход ----
  'от −60: отлично': 'from −60: excellent', '−60…−67: голос и видео': '−60…−67: voice and video', '−67…−72: данные': '−67…−72: data',
  '−72…−80: слабо': '−72…−80: weak', 'ниже −80: нет покрытия': 'below −80: no coverage', '3 и больше': '3 or more',
  '2: роуминг возможен': '2: roaming possible', '1: нет запасной AP': '1: no backup AP', '0: не слышно': '0: not heard',
  'Сигнал сети {s}': 'Signal of {s}', 'Сигнал подключения ноутбука': 'Laptop connection signal', 'Сколько BSS сети {s} слышно от −75': 'BSSs of {s} heard at −75 or better',
  'Обход с картой покрытия.': 'Survey with a coverage map.',
  'Загрузи план этажа, встань в точку и нажми на её место на плане: программа сделает скан и запомнит, что слышно в этой точке. По точкам строится карта покрытия выбранной сети.':
    'Load a floor plan, stand at a spot and click its place on the plan: the app scans and remembers what is heard there. The points build a coverage map of the selected network.',
  'Загрузить план этажа (PNG или JPG)': 'Load floor plan (PNG or JPG)', 'Открыть проект обхода': 'Open survey project',
  'Совет: точки ставь через 5–10 м и обязательно у границ помещений. Ноутбук держи так, как его держат пользователи.':
    'Tip: place points every 5–10 m and always near room boundaries. Hold the laptop the way users hold it.',
  'Замер': 'Measure', 'Просмотр': 'View', 'Что показывать на карте': 'What to show on the map', 'прозрачность': 'opacity', 'значения': 'values',
  'Сохранить проект': 'Save project', 'Открыть': 'Open', 'Карта в PNG': 'Map to PNG', 'Новый план': 'New plan', 'Удалить все точки': 'Delete all points',
  'Обычный вид': 'Normal view', 'Во весь экран': 'Full screen', 'Нажми на точку, чтобы увидеть подробности.': 'Click a point to see details.',
  'Встань в точку и нажми на её место на плане: скан займёт около 5 секунд.': 'Stand at a spot and click its place on the plan: the scan takes about 5 seconds.',
  'План этажа': 'Floor plan', 'план не загрузился': 'the plan did not load', 'Точка {n}: идёт скан…': 'Point {n}: scanning…', 'Точка {n}: ошибка скана': 'Point {n}: scan error',
  'Точка {n}': 'Point {n}', 'точек: {n}': 'points: {n}', ', ждут скан: {n}': ', waiting for scan: {n}', 'Сводка по слою': 'Layer summary',
  'Точек с данными': 'Points with data', 'Без запасной AP': 'No backup AP', 'Лучшая': 'Best', 'Худшая': 'Worst', 'Слабее −72': 'Weaker than −72',
  'Нажми на точку в режиме «Просмотр», чтобы увидеть, что слышно в ней.': 'Click a point in "View" mode to see what is heard there.',
  'Точек с данными пока нет.': 'No points with data yet.', 'Подключение': 'Connection', 'Слышно BSS': 'BSSs heard', 'нет сигнала': 'no signal', 'Удалить точку': 'Delete point',
  'Обход:': 'Survey:', 'План должен быть PNG или JPG.': 'The plan must be PNG or JPG.', 'План больше 8 МБ: уменьши картинку.': 'The plan is larger than 8 MB: make the image smaller.',
  'План не загружен:': 'Plan not loaded:', 'Точка не добавлена:': 'Point not added:', 'Обход': 'Survey',

  // ---- проблемы, beacon ----
  'По заданным правилам проблем не найдено.': 'No problems found by the configured rules.', 'Критично': 'Critical', 'Внимание': 'Warning', 'Информация': 'Info',
  'Подсвечено в таблице: {n} BSS.': 'Highlighted in the table: {n} BSS.', 'Нажми на проблему, чтобы подсветить затронутые BSS в таблице.': 'Click a problem to highlight the affected BSSs in the table.',
  'Сбросить': 'Reset', 'Что проверить:': 'What to check:', 'Выбери строку в таблице: здесь появятся все поля beacon с расшифровкой.': 'Select a row in the table to see every beacon field decoded.',
  '(локально администрируемый)': '(locally administered)', 'Диапазон и канал': 'Band and channel', '{b} ГГц, канал {c}, ширина {w} МГц, центр {x}': '{b} GHz, channel {c}, width {w} MHz, center {x}',
  'качество по драйверу {q}%': 'driver quality {q}%', 'Поколение': 'Generation', 'потоков: {n}': 'streams: {n}', 'legacy (без HT/VHT/HE)': 'legacy (no HT/VHT/HE)',
  'потоков {n}': '{n} streams', 'Макс. PHY-скорость': 'Max PHY rate', '{r} Мбит/с на {w} МГц (потолок по beacon, не текущая скорость)': '{r} Mbit/s at {w} MHz (ceiling from the beacon, not the current rate)',
  'Загрузка и станции': 'Load and stations', 'QBSS Load не вещается': 'QBSS Load not advertised', 'станций {n}': 'stations {n}', 'Размер IE': 'IE size',
  'Раскрыть все': 'Expand all', 'Свернуть все': 'Collapse all', 'Копировать BSSID': 'Copy BSSID', 'Копировать расшифровку': 'Copy decoding', 'IE не найдены': 'No IEs found',

  // ---- сравнение ----
  'Сделать текущий скан базовым': 'Use the current scan as baseline', 'Взять базу из файла снапшота': 'Load baseline from a snapshot file',
  'Сравнение показывает, что изменилось в эфире между двумя сканами: например, до и после правки на контроллере.': 'Compare shows what changed on air between two scans: for example, before and after a change on the controller.',
  'Зафиксируй базу сейчас, внеси изменения и сделай новый скан. Или возьми сохранённый ранее снапшот.': 'Set the baseline now, make your changes and scan again. Or use a previously saved snapshot.',
  'База:': 'Baseline:', 'Убрать базу': 'Remove baseline', 'База совпадает с текущим сканом. Сделай новый скан, и здесь появится разница.': 'The baseline is the current scan. Scan again to see the difference here.',
  'Изменились настройки': 'Settings changed', 'Появились': 'Appeared', 'Пропали': 'Disappeared', 'Сигнал изменился на {d} дБ и больше': 'Signal changed by {d} dB or more',
  'Без изменений: {n} BSS. Пропавшая BSS не всегда выключена: слабую точку скан может просто не услышать.': 'Unchanged: {n} BSS. A disappeared BSS is not necessarily off: a scan may simply miss a weak AP.',

  // ---- общее, плашки ----
  'Данных пока нет. Нажми «Сканировать», и здесь появятся графики.': 'No data yet. Click "Scan" and the charts will appear here.',
  'источник:': 'source:', 'журнал:': 'log:', 'Проверяю GitHub…': 'Checking GitHub…', 'Есть новая версия {v} (у тебя {c}).': 'A new version {v} is available (you have {c}).',
  'Открыть страницу релиза': 'Open the release page', 'Установлена последняя версия ({c}).': 'You have the latest version ({c}).', 'на GitHub {v}': 'on GitHub {v}',
  'Не удалось открыть:': 'Could not open:', 'Путь:': 'Path:', 'Закрыть': 'Close', 'Сканирую…': 'Scanning…', 'обновлено {t}': 'updated {t}',
  'Открыть параметры расположения': 'Open location settings', 'Ошибка скана:': 'Scan error:', 'Адаптеры недоступны:': 'Adapters unavailable:',
  'Нет связи с программой ({e}). Если окно долго было свёрнуто, подожди пару секунд; если сообщение не уходит - программа закрыта, запусти её снова.':
    'No connection to the app ({e}). If the window was minimized for a long time, wait a couple of seconds; if the message stays, the app is closed - start it again.',
  'Не удалось запустить скан:': 'Could not start the scan:', 'Не удалось скачать:': 'Download failed:', 'Не удалось подготовить отчёт:': 'Could not prepare the report:',
  'Отчёт открыт в новом окне: нажми Ctrl+P и выбери «Сохранить как PDF».': 'The report is open in a new window: press Ctrl+P and choose "Save as PDF".',
  'Готовлю PDF через Edge, это займёт несколько секунд…': 'Preparing the PDF with Edge, this takes a few seconds…',
  'Экспорт не удался: программа не ответила ({e})': 'Export failed: the app did not respond ({e})', 'Экспорт не удался:': 'Export failed:',
  'Открыть отчёт для печати (Ctrl+P → «Сохранить как PDF»)': 'Open the report for printing (Ctrl+P → "Save as PDF")', 'Не удалось задать базу:': 'Could not set the baseline:',
  '{w} скопирован в буфер обмена.': '{w} copied to the clipboard.', 'Не удалось скопировать: браузер запретил доступ к буферу обмена.': 'Could not copy: the browser denied clipboard access.',
  'Нажми «Удалить все точки» ещё раз, чтобы подтвердить.': 'Click "Delete all points" again to confirm.', 'Текст beacon': 'Beacon text',
  'Не удалось открыть снапшот:': 'Could not open the snapshot:', 'Не удалось прочитать файл:': 'Could not read the file:',
  'Программа остановлена. Окно можно закрыть.': 'The app has stopped. You can close the window.', 'Проект не открыт:': 'Project not opened:',
};

function T(s, args) {
  let r = LANG === 'en' && Object.prototype.hasOwnProperty.call(I18N_EN, s) ? I18N_EN[s] : s;
  if (args) r = r.replace(/\{(\w+)\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(args, k) ? String(args[k]) : m));
  return r;
}

// Перевод статической разметки index.html: текстовые узлы и подписи (placeholder, title, aria-label, alt).
function translateDom(root) {
  if (LANG === 'ru') return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const raw = n.nodeValue, key = raw.replace(/\s+/g, ' ').trim();
    if (key && Object.prototype.hasOwnProperty.call(I18N_EN, key)) {
      const lead = raw.match(/^\s*/)[0], tail = raw.match(/\s*$/)[0];
      n.nodeValue = (lead ? ' ' : '') + I18N_EN[key] + (tail ? ' ' : '');
    }
  }
  for (const el of root.querySelectorAll('[placeholder],[title],[aria-label],[alt]')) {
    for (const a of ['placeholder', 'title', 'aria-label', 'alt']) {
      const v = el.getAttribute(a);
      if (v && Object.prototype.hasOwnProperty.call(I18N_EN, v.trim())) el.setAttribute(a, I18N_EN[v.trim()]);
    }
  }
}
