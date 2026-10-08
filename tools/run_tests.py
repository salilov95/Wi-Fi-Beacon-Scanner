"""Запуск тестов в CI: как `python -m unittest discover -s tests`, но упавшие тесты дополнительно
выводятся аннотациями GitHub Actions (::error), чтобы причину было видно без чтения логов."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    tests_dir = os.path.join(ROOT, "tests")
    sys.path.insert(0, tests_dir)
    suite = unittest.defaultTestLoader.discover(tests_dir, top_level_dir=tests_dir)
    res = unittest.TextTestRunner(verbosity=1).run(suite)
    for kind, items in (("FAIL", res.failures), ("ERROR", res.errors)):
        for test, tb in items:
            tail = " | ".join(line.strip() for line in tb.strip().splitlines()[-6:])
            print("::error title=%s %s::%s" % (kind, test.id(), tail.replace("%", "%25")[:900]))
    print("::notice title=tests::%d тестов, упало %d, ошибок %d, пропущено %d" % (
        res.testsRun, len(res.failures), len(res.errors), len(res.skipped)))
    return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
