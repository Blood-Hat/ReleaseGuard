# Baseline result analysis

## Dataset composition

The processed OWASP BenchmarkJava data contains 2,740 labelled files across 11 categories:

| Category | Samples |
| --- | ---: |
| SQL injection | 504 |
| Weak randomness | 493 |
| Cross-site scripting | 455 |
| Path traversal | 268 |
| Command injection | 251 |
| Weak encryption | 246 |
| Weak hashing | 236 |
| Trust-boundary violation | 126 |
| Insecure cookie | 67 |
| LDAP injection | 59 |
| XPath injection | 35 |

The binary classes are close to balanced: 1,415 vulnerable and 1,325 non-vulnerable.

## Model comparison

Logistic regression achieved the stronger mean cross-validated result:

| Model | Accuracy | Precision | Recall | Specificity | Balanced accuracy | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 0.655 | 0.669 | 0.661 | 0.650 | 0.655 | 0.664 |
| Gaussian Naive Bayes | 0.549 | 0.582 | 0.438 | 0.666 | 0.552 | 0.492 |

The logistic model improves balanced accuracy above the 0.5 chance/constant-class baseline. Its recall of about 0.661 also means roughly one third of vulnerable cases remain missed at the default threshold. It is therefore a prioritisation baseline, not a standalone security control.

## Interpreting coefficients carefully

The largest standardised logistic coefficients by absolute magnitude include:

| Feature | Coefficient |
| --- | ---: |
| Rule findings | +0.957 |
| Cryptographic operations | −0.933 |
| Maximum line length | +0.563 |
| Database sinks | −0.261 |
| Complexity density | +0.236 |
| Request-parameter sources | +0.234 |

A positive coefficient increases the model's estimated risk when other inputs are held constant; a negative value decreases it. These are associations within this generated benchmark. For example, a negative cryptography coefficient does **not** mean cryptographic code is inherently safe. It can reflect how OWASP generated vulnerable and safe variants. Coefficients must not be interpreted as causes.

## Demonstration result

The bundled demonstration intentionally contains vulnerable and safe examples. The gate correctly fails because of one critical and four high static findings, a zero security score after penalties, and four files above the configured ML high-risk threshold.

The synthetic failure series fits the Goel–Okumoto model with R² 0.99056 and estimates about 3.49 residual faults. This only verifies the implementation; it is not a real case-study result.

One safe demonstration file is classified as vulnerable by the ML model. That false positive is retained deliberately because it illustrates why predictions require human review and why precision is measured.

## What the results justify

The baseline supports three conclusions:

1. The pipeline genuinely learns from labelled data and generalises better than chance-level balanced accuracy on held-out folds.
2. Simple interpretable features capture some vulnerability-related structure but leave substantial room for improvement.
3. Combining ML prioritisation with concrete static findings and reliability evidence is more defensible than treating the probability alone as a release decision.

It does not justify a claim of production-grade detection or external generalisation.

