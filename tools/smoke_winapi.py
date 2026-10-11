"""CI (Windows): новые вызовы Windows API работают на настоящей системе - GetAdaptersInfo (IPv4 и аренда DHCP)
и чтение журнала WLAN-AutoConfig через wevtapi. Результат - аннотациями; Wi-Fi на сервере CI нет, поэтому
журнал может отсутствовать - это не ошибка, важно, что вызов не падает."""
import sys

from wifi_beacon_scanner import ip_win


def main() -> int:
    ok = True
    ad = ip_win.list_adapters()
    with_ip = [a for a in ad if a["ip"] and a["ip"] != "0.0.0.0"]
    if not ad:
        print("::error title=iphlpapi::GetAdaptersInfo не вернул ни одного адаптера")
        ok = False
    else:
        a = with_ip[0] if with_ip else ad[0]
        print("::notice title=iphlpapi::адаптеров %d, с IPv4 %d; %s: %s, DHCP=%s, сервер %s, аренда %s" % (
            len(ad), len(with_ip), a["description"][:40], a["ip"], a["dhcp"], a["dhcp_server"] or "-", a["lease"]))
        info = ip_win.adapter_ip(a["name"])
        if not info or info["ip"] != a["ip"]:
            print("::error title=iphlpapi::adapter_ip не нашёл адаптер по имени %s" % a["name"])
            ok = False
    try:
        from wifi_beacon_scanner.winlog_win import read_events
        ev = read_events(24 * 7)
        print("::notice title=winlog::журнал WLAN-AutoConfig прочитан: событий за неделю %d%s" % (
            len(ev), (", пример: %s %s" % (ev[0]["id"], ev[0]["message"][:60])) if ev else ""))
    except OSError as e:
        print("::notice title=winlog::журнал недоступен (ожидаемо на сервере без Wi-Fi): %s" % e)
    except Exception as e:  # noqa: BLE001
        print("::error title=winlog::%s: %s" % (type(e).__name__, e))
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
