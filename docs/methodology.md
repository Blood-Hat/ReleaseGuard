# Methodology

## Research design

This is a quantitative, design-and-evaluation study. A working artefact is built, evaluated on a labelled dataset, and demonstrated on a controlled Java project. The implementation and the empirical claims are deliberately separated.

## Dataset

The ML dataset is produced from OWASP BenchmarkJava version 1.2:

- 2,740 Java test cases matched to ground-truth rows;
- 1,415 labelled vulnerable;
- 1,325 labelled non-vulnerable;
- each label includes a vulnerability category and CWE identifier.

The ground-truth target is the `real vulnerability` field. The `category` and `cwe` fields are retained for analysis but are not used as input features, because using them would leak the answer.

## Feature engineering

Each Java file becomes one numeric row with 22 features:

- size and structure: physical/logical lines, classes, methods;
- complexity: cyclomatic complexity and density;
- maintainability: comment ratio, maximum line length, TODO/FIXME count;
- explainable rule signals: total and high-risk rule findings;
- API/source/sink patterns: request parameters, headers, database calls, response output, file operations, redirects, cookies, cryptography, concatenation, prepared statements, and validation/encoding calls.

These features are intentionally interpretable. They form a baseline; they do not capture complete data flow or program semantics.

## Candidate models

### Logistic regression

Features are standardised using statistics learned only from the training portion of each fold. The implementation uses weighted binary cross-entropy so the positive and negative classes receive balanced influence, plus L2 regularisation.

### Gaussian Naive Bayes

For each class and feature, the model estimates a mean and variance and applies Bayes' rule under a conditional-independence and Gaussian assumption.

Both implementations use only Python's standard library. This makes every calculation inspectable and avoids hiding the learning process behind a high-level library.

## Evaluation protocol

- deterministic random seed: 42;
- stratified five-fold cross-validation;
- every sample appears in a test fold once;
- model selection: highest mean F1, then recall, then balanced accuracy;
- reported metrics: accuracy, precision, recall/sensitivity, specificity, balanced accuracy, F1, and confusion matrix.

F1 and balanced accuracy are emphasised because vulnerability detection must consider both missed vulnerabilities and false alarms.

## Verified result

| Model | Accuracy | Precision | Recall | Specificity | Balanced accuracy | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 0.655474 | 0.669087 | 0.660777 | 0.649811 | 0.655294 | 0.664350 |
| Gaussian Naive Bayes | 0.548540 | 0.581825 | 0.438163 | 0.666415 | 0.552289 | 0.492432 |

Logistic regression was selected and refitted on all 2,740 rows for deployment. The fold-level confusion matrices remain available in `results/ml_evaluation.json`.

## Static analysis

Ten transparent rules identify selected patterns such as dynamic SQL, hard-coded credentials, weak hashes, unsafe native deserialisation, OS command execution, predictable randomness, permissive CORS, stack-trace disclosure, and legacy SSL use. Each finding has a stable rule ID, severity, CWE, file, line, evidence, and remediation.

The rules provide inspectable evidence but are intentionally conservative in their claims. Regex matching is not equivalent to compiler-grade data-flow analysis.

## Reliability model

The input contains test time and cumulative failures. ReleaseGuard fits the Goel–Okumoto non-homogeneous Poisson process:

```text
m(t) = a × (1 − exp(−b × t))
```

where:

- `m(t)` is expected cumulative detected faults by time `t`;
- `a` is the estimated total number of detectable faults;
- `b` is the fault-detection rate.

The implementation searches a deterministic logarithmic range of `b` values. For each candidate, it calculates the least-squares optimal `a`, then keeps the pair with the lowest squared error. It reports residual faults, current failure intensity, an MTTF proxy, and R².

## Release decision

The default overall score weights are:

- security: 50%;
- maintainability: 20%;
- reliability: 30%.

Hard thresholds remain decisive. For example, the default gate fails when there is any critical/high static finding, any ML prediction above the configured high-risk probability, insufficient scores, excessive estimated residual faults, missing required reliability evidence, or a poor reliability-model fit.

## Reproducibility

The dataset preparation, training, prediction, reporting, and tests are command-line operations stored in the repository. The saved model includes its feature order, scale parameters, model coefficients, threshold, class counts, seed, fold count, and complete evaluation summary.

## Threats to validity

- **Construct validity:** OWASP's synthetic test cases simplify real application behaviour.
- **Internal validity:** generated test variants can share structural patterns across random folds, making performance optimistic.
- **External validity:** performance on OWASP does not establish performance on arbitrary industrial Java systems.
- **Conclusion validity:** two simple baseline models are not enough to claim superiority over modern ML or deep-learning methods.
- **Reliability-model validity:** irregular testing effort or changing test strategy can violate model assumptions.

Future experiments should use grouped/project-wise splits, additional real-world datasets, stronger classifiers, feature ablation, calibration, and confidence intervals.

