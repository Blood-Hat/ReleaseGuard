from pathlib import Path
import unittest

from releaseguard.benchmark import evaluate_manifest


ROOT = Path(__file__).parents[1]


class BenchmarkTests(unittest.TestCase):
    def test_bundled_smoke_benchmark(self) -> None:
        result = evaluate_manifest(ROOT / "examples" / "benchmark" / "labels.csv")
        self.assertEqual(8, result["samples"])
        self.assertEqual(1.0, result["recall"])
        self.assertEqual(1.0, result["precision"])


if __name__ == "__main__":
    unittest.main()

