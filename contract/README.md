# Contract

**English** · [Русский](README.ru.md)

What the program must output for a fixed set of scans. This is the agreement between the Python
version (1.x) and the Rust + Tauri version (2.x, in development): given the same input, both must produce the
same result. It also protects 1.x itself — any change in parsing or rules shows up as a diff here.

| Path | What |
|---|---|
| `fixtures/*.json` | Input: scan snapshots (the same format as *Export → JSON*) |
| `golden/<fixture>.<lang>.json` | Expected output for each snapshot, in Russian and English |
| `schema/golden.schema.json` | Format of the expected output (JSON Schema 2020-12) |

The expected output contains, for every snapshot:

- `bss` — every network row as the table and the *Beacon* tab see it, including the decoded IE tree;
- `findings` — the *Problems* tab;
- `advice` — channel quality for 2.4 and 5 GHz (`count` = BSS, `radios` = radios);
- `util` — channel utilisation from QBSS Load.

## Fixtures

| Fixture | Source |
|---|---|
| `real-home-01` | a real scan (MediaTek MT7921, Windows 11), anonymised |
| `demo-office` | the demo mode (`DemoBackend`) |
| `synthetic-edge` | hand-built edge cases: deprecated VHT widths, AKM 23/24/25, FILS, 6 GHz channel 2, one radio with several SSIDs |

Real scans are anonymised before they are committed: the repository is public, and a scan contains neighbours'
network names, BSSIDs and, in WPS, router models and serial numbers.

    python tools/anonymize_snapshot.py scan.json contract/fixtures/real-<place>-NN.json

SSIDs become `net-01…`, BSSIDs keep the vendor OUI and the low 4 bits (so vendor lookup and radio grouping
stay the same), WPS and vendor IE text is wiped. The tool refuses to write the file if any original SSID or
BSSID is still inside. Do not commit the original scan or the `--map` file.

## Commands

    python tools/golden.py check     # recompute and compare (also run by tests/test_contract.py)
    python tools/golden.py diff      # show what differs
    python tools/golden.py update    # rewrite golden files — only when the change is intended

Numbers are compared with a tolerance of 1e-6. Values are already rounded by the program; the tolerance only
covers last-bit differences between platforms.

## Rules

1. A change that alters `golden/` must be intended, explained in the CHANGELOG and committed together with
   the regenerated files (`update`). A pull request with an unexplained golden diff is a regression.
2. A new fixture is added to `fixtures/`, then `update`; both languages are generated.
3. A new field in the output is added to the schema first. The `contract` number goes up only when an
   existing field changes meaning or type.
4. The Rust version reads the same `fixtures/` and compares its output with the same `golden/` files.
