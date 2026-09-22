from pathlib import Path
import csv
import tempfile
import unittest

from releaseguard.features import FEATURE_NAMES, extract_features
from releaseguard.ml import predict_target, train_and_compare


ROOT = Path(__file__).parents[1]


class MachineLearningTests(unittest.TestCase):
    def test_feature_schema_is_stable(self) -> None:
        features = extract_features(
            ROOT / "examples" / "benchmark" / "vulnerable" / "VulnerableLogin.java"
        )
        self.assertEqual(FEATURE_NAMES, list(features))
        self.assertGreater(features["database_sinks"], 0)

    def test_train_compare_save_and_predict(self) -> None:
        sample_root = ROOT / "examples" / "benchmark"
        labelled = []
        for folder, label in (("vulnerable", 1), ("safe", 0)):
            for path in sorted((sample_root / folder).glob("*.java")):
                labelled.append((path, label))
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            dataset = temp / "features.csv"
            with dataset.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["path", "label", *FEATURE_NAMES])
                writer.writeheader()
                for path, label in labelled:
                    writer.writerow({"path": path.name, "label": label, **extract_features(path)})
            model = temp / "model.json"
            metrics = temp / "metrics.json"
            result = train_and_compare(dataset, model, metrics)
            self.assertIn(result["selected_model"], {"logistic_regression", "gaussian_naive_bayes"})
            self.assertTrue(model.exists())
            predictions = predict_target(model, sample_root / "vulnerable")
            self.assertEqual(4, len(predictions))


if __name__ == "__main__":
    unittest.main()
