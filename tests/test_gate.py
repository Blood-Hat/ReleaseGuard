from pathlib import Path
import tempfile
import unittest

from releaseguard.models import Assessment
from releaseguard.reliability import analyze_failure_csv
from releaseguard.reports import write_reports
from releaseguard.scanner import scan_target
from releaseguard.scoring import assess_gate


ROOT = Path(__file__).parents[1]


class GateTests(unittest.TestCase):
    def test_vulnerable_sample_fails_gate_and_writes_all_reports(self) -> None:
        target = ROOT / "examples" / "benchmark"
        findings, metrics = scan_target(target)
        reliability = analyze_failure_csv(ROOT / "examples" / "failure-data.csv")
        scores, gate = assess_gate(findings, metrics, reliability)
        self.assertEqual("FAIL", gate["decision"])
        assessment = Assessment(
            target=str(target),
            generated_at="2026-01-01T00:00:00+00:00",
            findings=findings,
            metrics=metrics,
            reliability=reliability,
            scores=scores,
            gate=gate,
        )
        with tempfile.TemporaryDirectory() as directory:
            paths = write_reports(assessment, Path(directory))
            self.assertEqual(4, len(paths))
            self.assertTrue(all(path.exists() for path in paths))


if __name__ == "__main__":
    unittest.main()

