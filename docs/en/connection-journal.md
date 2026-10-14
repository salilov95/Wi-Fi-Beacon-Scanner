# Connection journal and sessions

[← README](../../README.md) · [Русский](../ru/connection-journal.md)

What is recorded:

- **roam** - BSSID change within a network: how long the laptop stayed on the previous BSS, RSSI before and after;
- **disconnect** - loss of connectivity, its duration and the reason from Windows (`WlanReasonCodeToString` text);
- **ping-pong** - A → B → A within 30 s;
- **sticky client** - the laptop holds on to a BSS weaker than −75 dBm while a BSS of the same network is heard
  8 dB stronger for more than 10 s;
- **failed connection** - the attempt failed, with the reason;
- **MCS from rate** - estimate of MCS, spatial streams and width from the Rx/Tx rates
  (see [MCS](diagnostics.md#mcs-and-maximum-rate)).

Chart window: 1, 5, 15 or 30 minutes. The journal is exported to CSV and included in PDF and Excel reports.

## How it works and what has not been verified

The main source is polling the current connection once per second (`WlanQueryInterface`): BSSID changes become
roams, state changes become disconnects. Reasons for disconnects and failed connections come from
`WlanRegisterNotification` (ACM) notifications and are labeled with Windows' own text (`WlanReasonCodeToString`).
According to the documentation, MSM notifications require the `wiFiControl` capability; if Windows refuses,
the app subscribes to ACM only - roams are still visible from polling. The mode is shown in the tab's status line.

Notification codes start at 0 in the mingw-w64 headers and at 0x1000 for ACM on the Microsoft page; the app
accepts both. At the bottom of the tab there are "Raw Windows notifications" - if an event is not recognized,
you can see exactly what arrived. Verified on a laptop with MediaTek Wi-Fi 6 MT7921 (Windows 11): scanning,
journal, sessions and the Windows event log work; parsing of 802.1X failure reasons has not yet been checked
against real failures.

## Connection sessions (client state machine)

The Sessions tab. A session is one connection attempt or one roam. Sources, none of them needs admin rights:

| Source | What it provides |
|---|---|
| ACM (`WlanRegisterNotification`) | connection start, result, failed attempt with reason, disconnect |
| MSM | associating → associated → authenticating → connected, roaming start/end, disassociating |
| ONEX (802.1X) | authentication result, failure reason, EAP error code, EAP type, machine or user credentials, 802.1X restarts |
| `GetAdaptersInfo` | IPv4, DHCP server, lease time (`LeaseObtained`) |
| `Microsoft-Windows-WLAN-AutoConfig/Operational` event log (`wevtapi`) | the Windows log tab: loads the last day on start, refreshes every minute; events around a session are shown in its details |

Durations:

- **Association** - associating → associated.
- **Authentication** - authenticating → connected. For 802.1X this is the whole EAP exchange plus the 4-way
  handshake, for PSK - the 4-way handshake. Windows does not report the 4-way handshake separately, so the two
  cannot be split without a packet capture.
- **Total** - from the start of the connection (for a roam - from the start of association with the new AP)
  to connected.
- **To IPv4** - from connected to the new DHCP lease (that is, a completed DORA; the time is taken from the lease
  itself, 1 s resolution) or until the address appears. If the address was kept from the previous connection and
  there was no new lease, the session says so: there was no wait. 169.254.x.x is labeled as "DHCP server did not
  respond".

Time colors: roam up to 100 ms green, up to 300 ms yellow; connection up to 2 s and up to 5 s; IP up to 1 s and up to 3 s.

Not yet verified on a real laptop:

- the 802.1X (ONEX) data layout is based on the Windows SDK headers. The bytes of every 802.1X notification are
  kept in "Raw notifications" on the Connection tab, so the parser can be corrected from them;
- whether a regular user can read the WLAN-AutoConfig log depends on policy. If not, the tab shows the reason.

Sessions are exported to CSV and included in PDF/HTML/Excel reports (the "Sessions" sheet).
