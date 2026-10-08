"""Точка входа для .exe (PyInstaller). Делает то же, что `python -m wifi_diag gui`."""
import sys

from wifi_diag.__main__ import main

if __name__ == "__main__":
    sys.exit(main(["gui"] + sys.argv[1:]))
