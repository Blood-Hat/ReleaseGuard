# Research sources and attribution

This page records what each outside source contributed. Citation of a paper or standard does not mean its authors reviewed or endorsed ReleaseGuard.

## Academic guidance and Dr. Rana Majumdar's research

**Academic mentor:** Dr. Rana Majumdar, Sister Nivedita University. His [Google Scholar profile](https://scholar.google.com/citations?user=GvubxL4AAAAJ&hl=en) and [ORCID record](https://orcid.org/0000-0001-7081-5801) identify his software reliability research.

1. Majumdar, R., Kapur, P. K., Khatri, S. K., and Shrivastava, A. K. (2019). [“Effort-based software release and testing stop time decisions.”](https://doi.org/10.1504/IJRS.2019.101318) *International Journal of Reliability and Safety*, 13(3), 179–193. **Role here:** motivates assessing whether to release or continue testing. The paper proposes a testing effort cost model; ReleaseGuard does not implement that cost model.

2. Choudhary, C., Kapur, P. K., Khatri, S. K., and Majumdar, R. (2021). [“Software Quality and Reliability Improvement in Open Environment.”](https://doi.org/10.1007/978-981-16-0037-1_21) In *Advances in Interdisciplinary Research in Engineering and Business Management*, pp. 263–276. **Role here:** motivates evaluating software readiness using multiple criteria. The chapter's AHP and entropy weighting are not implemented here; ReleaseGuard uses explicitly configured weights and hard thresholds.

3. Majumdar, R., Kapur, P. K., and Khatri, S. K. (2016). [“Measuring testing efficiency & effectiveness for software upgradation and its impact on CBP.”](https://doi.org/10.1109/ICICCS.2016.7542347) *2016 1st International Conference on Innovation and Challenges in Cyber Security*. **Role here:** background for measuring testing effectiveness before delivery. No numerical result from this paper is claimed as a ReleaseGuard result.

4. Selvi, K., and Majumdar, R. (2014). [“Applying Six Sigma Techniques to Reduce the Number of Defects of Software.”](http://www.ijates.com/ADMIN/admin/postimages/images/fullpdf/1412177821_439.pdf) **Role here:** background on defect reduction. Six Sigma is not implemented in ReleaseGuard.

## Implemented reliability model

Goel, A. L., and Okumoto, K. (1979). [“Time-Dependent Error-Detection Rate Model for Software Reliability and Other Performance Measures.”](https://doi.org/10.1109/TR.1979.5220566) *IEEE Transactions on Reliability*, 28(3), 206–211. **Role here:** source of the cumulative-failure reliability growth model `m(t) = a(1 − exp(−bt))` fitted by ReleaseGuard. This model is distinct from the three Majumdar research approaches above.

## Dataset and security vocabulary

- **OWASP Benchmark Project.** [BenchmarkJava source](https://github.com/OWASP-Benchmark/BenchmarkJava), [project description](https://owasp.org/projects/benchmark), and [version 1.2 labels at the exact experimental revision](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/20cbf3d11123347e47ed89541e6942836def53f7/expectedresults-1.2.csv). **Role here:** Java test cases and ground-truth vulnerability labels for the ML experiment. Upstream [GPL-2.0 licence](https://github.com/OWASP-Benchmark/BenchmarkJava/blob/20cbf3d11123347e47ed89541e6942836def53f7/LICENSE).
- **MITRE.** [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/). **Role here:** standard identifiers for weakness categories and static rules.
- **NIST.** [Secure Software Development Framework, SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final). **Role here:** secure development lifecycle context. ReleaseGuard does not claim SSDF certification or full compliance.
- **OASIS.** [SARIF 2.1.0](https://www.oasis-open.org/standard/sarifv2-1-os/). **Role here:** format specification for exported static analysis results.

## Original work and experimental limits

ReleaseGuard's feature extraction, model training, gate configuration, reporting, and demonstration code are the project's implementation. The sample eight-file demonstration and `examples/failure-data.csv` are authored for this project; the failure series is synthetic. The reported 2,740-row ML metrics come from the credited OWASP benchmark and can be reproduced with the instructions in the README.
