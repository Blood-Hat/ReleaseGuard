# Model artefacts

`vulnerability_model.json` is the selected logistic-regression baseline trained on all 2,740 prepared OWASP BenchmarkJava samples after five-fold model comparison.

The JSON contains:

- exact ordered feature schema;
- standardisation means and deviations;
- learned coefficients and intercept;
- classification threshold;
- sample and class counts;
- seed and validation protocol;
- fold-level comparison metrics.

It is intentionally JSON rather than an opaque binary pickle so that the model remains inspectable and safer to load. Retrain it whenever the feature schema or source dataset changes.

