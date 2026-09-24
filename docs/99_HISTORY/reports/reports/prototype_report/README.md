# Prototype report sources

LaTeX and Word sources for the Sudarshan prototype progress and engineering benchmark report.

> **Point-in-time artifact.** The report was written against commit `ec7e6ff` and the corpus record at commit `ce30610`. It is not maintained against later changes to the platform. For the current state see [`../README.md`](../README.md), [`../FEATURE_STATUS.md`](../FEATURE_STATUS.md) and [`../KNOWN_LIMITATIONS.md`](../KNOWN_LIMITATIONS.md).

Two renditions of the same report, one per supplied IEEE template:

| File | Template | Notes |
|---|---|---|
| `Sudarshan_Prototype_Report.tex` | `Prototype_Template_CyberShield` (`spconf.sty` + `IEEEbib.bst`, ICASSP two-column) | Source of truth. Auto-numbered equations and cross-references. |
| `Sudarshan_Prototype_Report.docx` | `Prototype_template.docx` (IEEE Word, two-column) | Generated to match section for section: 9 sections, 15 numbered equations, 4 tables. |

Both carry identical content. The `.docx` equation numbers are static, so if you
add or remove an equation there, update the in-text references by hand — they
are the strings `equation (2)`, `equation (12)`, and `equations (14) and (15)`.
The `.tex` resolves these automatically via `\ref`.

## Build (LaTeX)

```bash
pdflatex Sudarshan_Prototype_Report.tex && pdflatex Sudarshan_Prototype_Report.tex
```

Two passes are needed to resolve cross-references. No `bibtex` pass is required:
the bibliography is an inline `thebibliography` block, so the document compiles
with `spconf.sty` alone. `IEEEbib.bst` is retained for anyone who prefers to
switch back to `\bibliography{refs}`.

Packages used beyond the template's own: `amsmath`, `amssymb`, `booktabs`,
`array` — all standard in TeX Live and on Overleaf.

## Evidentiary policy

Every quantitative claim in the report is traceable to one of:

- a file path in this repository (verified at commit `ec7e6ff`), or
- `docs/evaluation/corpus_static_validation.json` — the machine-generated
  17-sample corpus record, git commit `ce30610`, results digest
  `1f9cd4c20c23f70ded221dcb2f5505a70c454854c4c66ca7011620d053ea5f6e`.

Where the project's design notes disagree with the implemented code, the code is
treated as authoritative and the discrepancy is enumerated in Section 7
("Adversarial Review: Discrepancies and Limitations"). Eight such items are
recorded. No figure from `docs/evaluation/BENCHMARKS.md` is cited as verified,
because that document carries its own "not verified" warning.

## Structure

| § | Section | Grounded in |
|---|---------|-------------|
| 1 | Introduction | — |
| 2 | Threat model & architecture | `analyzers/`, `services/`, `routes/runtime_api.py` |
| 3 | VIDE engine | `engines/vide/{color_match,view_ast,compare,signer_registry}.py` |
| 4 | Dynamic instrumentation & anti-evasion | `engines/frida_hooks/{banking_trojan,time_warp}.js`, `engines/persona.py` |
| 5 | Risk formulation | `engines/{risk_engine,bfci_scorer,execution_assertions}.py` |
| 6 | Evaluation | `docs/evaluation/corpus_static_validation.json` + third-party reports |
| 7 | Adversarial review | discrepancies between design notes and code |
| 8 | Regulatory alignment | `risk_engine._get_recommended_action` |
| 9 | Conclusion & roadmap | — |
