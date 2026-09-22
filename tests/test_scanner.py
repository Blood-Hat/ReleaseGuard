from pathlib import Path
import unittest

from releaseguard.scanner import scan_file, scan_target


ROOT = Path(__file__).parents[1]


class ScannerTests(unittest.TestCase):
    def test_vulnerable_samples_raise_high_risk_findings(self) -> None:
        findings, metrics = scan_target(ROOT / "examples" / "benchmark" / "vulnerable")
        rule_ids = {item.rule_id for item in findings}
        self.assertTrue({"RG001", "RG002", "RG003", "RG005", "RG007"}.issubset(rule_ids))
        self.assertEqual(4, len(metrics))

    def test_safe_samples_have_no_high_or_critical_findings(self) -> None:
        findings, _ = scan_target(ROOT / "examples" / "benchmark" / "safe")
        self.assertFalse(any(item.severity in {"critical", "high"} for item in findings))

    def test_metrics_are_collected(self) -> None:
        _, metrics = scan_file(
            ROOT / "examples" / "benchmark" / "safe" / "SafeProcess.java",
            ROOT / "examples" / "benchmark",
        )
        self.assertGreater(metrics.lines_of_code, 0)
        self.assertGreaterEqual(metrics.methods, 1)
        self.assertGreaterEqual(metrics.cyclomatic_complexity, 2)


if __name__ == "__main__":
    unittest.main()

