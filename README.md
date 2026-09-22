# ReleaseGuard

An explainable research prototype for assessing Java software before release using vulnerability prediction, traceable static findings, and software reliability growth.

## Research question

Can lightweight machine learning, source level security evidence, and test failure history support an auditable decision to release a Java application or continue testing it?

ReleaseGuard is developed by **Abhra Chowdhury** under the academic guidance of **Dr. Rana Majumdar, Sister Nivedita University**. Dr. Majumdar's published work on testing effort and software readiness informs the research question. The implementation uses a separate Goel–Okumoto reliability growth model and the OWASP BenchmarkJava dataset; it does not reproduce Dr. Majumdar's cost optimisation or AHP/entropy algorithms. Full attribution is in [Research sources](docs/references.md).

## Method

1. Match Java test cases to the official OWASP BenchmarkJava 1.2 ground truth and extract 22 numeric source features.
2. Compare logistic regression and Gaussian Naive Bayes with stratified five fold cross validation (seed 42).
3. Apply the selected model to Java files, alongside ten explainable CWE mapped static checks and source metrics.
4. Fit the Goel–Okumoto model to cumulative test failures.
5. Apply documented thresholds and export the release decision with supporting evidence.

The [methodology](docs/methodology.md) describes the features, models, thresholds, evaluation protocol, and validity limits.

## Baseline experiment

The experiment matched **2,740** OWASP Java test cases: 1,415 vulnerable and 1,325 non vulnerable. Results below are averages across five held out folds.

| Model | Accuracy | Precision | Recall | F1 | Balanced accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 0.655 | 0.669 | 0.661 | **0.664** | 0.655 |
| Gaussian Naive Bayes | 0.549 | 0.582 | 0.438 | 0.492 | 0.552 |

Logistic regression was selected for the current model. These are baseline results on a synthetic benchmark. They are not a claim of performance on unrelated production applications. Fold level confusion matrices and the selection record are in [results/ml_evaluation.json](results/ml_evaluation.json); interpretation is in [docs/results-analysis.md](docs/results-analysis.md).

## Reproduce the experiment

Requires Python 3.11 or newer and Git. The implementation uses only Python's standard library.

```powershell
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git datasets/raw/BenchmarkJava
python -m releaseguard prepare-owasp datasets/raw/BenchmarkJava --output datasets/processed/owasp_features.csv
python -m releaseguard train datasets/processed/owasp_features.csv --model-output models/vulnerability_model.json --metrics-output results/ml_evaluation.json --seed 42
python -m unittest discover -s tests -v
```

The baseline used upstream commit [`20cbf3d11123347e47ed89541e6942836def53f7`](https://github.com/OWASP-Benchmark/BenchmarkJava/commit/20cbf3d11123347e47ed89541e6942836def53f7). For an exact repeat, check out that revision after cloning. The raw benchmark and generated feature table are excluded from this repository; see [dataset provenance](datasets/README.md).

Run the included test project through the assessment:

```powershell
python -m releaseguard scan examples/benchmark --failures examples/failure-data.csv --model models/vulnerability_model.json --config config/releaseguard.json --output results/demo --no-fail-on-gate
```

The example contains deliberately vulnerable code, so the expected gate result is **FAIL**. Open `results/demo/report.html` to inspect the reasoning. The failure CSV is synthetic demonstration data; a real case study needs recorded testing observations.

## Outputs and scope

The scanner writes JSON, Markdown, HTML, and SARIF reports. It records the rule, CWE, severity, file and line for static findings; per file ML probabilities; reliability estimates; scores; and the thresholds behind the gate decision.

The repository contains the implementation (`releaseguard/`), tests (`tests/`), demonstration inputs (`examples/`), configuration (`config/`), model (`models/`), evaluation record (`results/ml_evaluation.json`), and research documentation (`docs/`).

The current model is a baseline. Its simple features miss some vulnerable cases, random folds may share benchmark generator patterns, regex checks do not perform full Java data flow analysis, and the reliability model depends on stable test conditions. ReleaseGuard provides decision support; a passing gate does not certify that software is secure.

## Attribution

- **Research guidance:** Dr. Rana Majumdar and coauthors' work on testing effort, release decisions, and software readiness, with exact citations and the role of each paper in [docs/references.md](docs/references.md).
- **Reliability model:** Goel and Okumoto (1979), cited in [docs/references.md](docs/references.md).
- **ML data:** [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), including its labelled ground truth and [GPL-2.0 licence](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/20cbf3d11123347e47ed89541e6942836def53f7/LICENSE).
- **Weakness identifiers and report format:** [MITRE CWE](https://cwe.mitre.org/) and [OASIS SARIF 2.1.0](https://www.oasis-open.org/standard/sarifv2-1-os/).
- **Secure development context:** [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final).

This repository is an independent student research prototype. The cited authors and organisations have not endorsed its implementation or results. See also [third party notices](THIRD_PARTY_NOTICES.md).
