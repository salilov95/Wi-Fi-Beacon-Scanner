"""Пишет файл версии для PyInstaller (--version-file): номер версии и описание видны
в свойствах WifiDiag.exe и в инвентаризации ПО. Номер берётся из wifi_diag/__init__.py.

Запуск из корня проекта:  python installer/version_info.py build/version_info.txt
Печатает номер версии (его подхватывает build_installer.bat).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from wifi_diag import __version__  # noqa: E402

TEMPLATE = """VSVersionInfo(
  ffi=FixedFileInfo(filevers={t}, prodvers={t}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                    date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'salilov95'),
      StringStruct('FileDescription', 'WifiDiag - Wi-Fi scanner and diagnostics'),
      StringStruct('FileVersion', '{v}'),
      StringStruct('InternalName', 'WifiDiag'),
      StringStruct('OriginalFilename', 'WifiDiag.exe'),
      StringStruct('ProductName', 'WifiDiag'),
      StringStruct('ProductVersion', '{v}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main(argv):
    parts = [int(x) for x in __version__.split(".")[:3]]
    t = tuple(parts + [0] * (4 - len(parts)))
    out = argv[1] if len(argv) > 1 else os.path.join(ROOT, "build", "version_info.txt")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.format(t=t, v=__version__))
    print(__version__)


if __name__ == "__main__":
    main(sys.argv)
