from pathlib import Path
import unittest

from releaseguard.reliability import analyze_failure_csv, fit_goel_okumoto


ROOT = Path(__file__).parents[1]


class ReliabilityTests(unittest.TestCase):
    def test_demo_data_fits_growth_model(self) -> None:
        estimate = analyze_failure_csv(ROOT / "examples" / "failure-data.csv")
        self.assertEqual("Goel-Okumoto NHPP", estimate.model)
        self.assertGreater(estimate.r_squared, 0.9)
        self.assertGreaterEqual(estimate.estimated_total_faults, estimate.observed_failures)

    def test_rejects_too_few_observations(self) -> None:
        with self.assertRaises(ValueError):
            fit_goel_okumoto([(1.0, 1.0), (2.0, 2.0)])


if __name__ == "__main__":
    unittest.main()

