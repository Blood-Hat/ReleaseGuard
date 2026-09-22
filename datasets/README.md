# Datasets

## Primary ML dataset

ReleaseGuard uses [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), a runnable Java vulnerability-detection benchmark maintained by the OWASP Benchmark project. The baseline experiment used upstream commit [`20cbf3d11123347e47ed89541e6942836def53f7`](https://github.com/OWASP-Benchmark/BenchmarkJava/commit/20cbf3d11123347e47ed89541e6942836def53f7).

Expected local layout:

```text
datasets/
├── raw/
│   └── BenchmarkJava/          ignored third-party Git clone
└── processed/
    └── owasp_features.csv     generated 22-feature dataset, ignored by Git
```

The label source is [`expectedresults-1.2.csv`](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/20cbf3d11123347e47ed89541e6942836def53f7/expectedresults-1.2.csv) with these relevant columns:

- `test name`;
- `category`;
- `real vulnerability`;
- `cwe`.

The current preparation run matched all 2,740 ground-truth rows to source files: 1,415 vulnerable and 1,325 non-vulnerable.

## Provenance and licence

The raw benchmark is not authored by this project and is not committed here. Its upstream [LICENSE](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/20cbf3d11123347e47ed89541e6942836def53f7/LICENSE) is GPL-2.0. The generated feature table is derived from its source files and labels and is also excluded from this repository; reproduce it locally from the credited source. Preserve OWASP attribution if sharing a derived dataset separately.

## Why not Kaggle?

Kaggle is a distribution platform, not a guarantee of provenance or label quality. OWASP BenchmarkJava was selected from its official project repository because its purpose, source, labels, and CWE mapping are inspectable. A Kaggle dataset can be added later only after its original source, licence, schema, and label-generation method are verified.

## Reliability data

`examples/failure-data.csv` is synthetic demonstration data and must not be reported as an empirical result. The final case study must replace it with cumulative failures recorded during a real, stable testing process.
