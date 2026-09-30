# What Did This Patch Remove?

Code, data, and labels for the article *What Did This Patch Remove?* 

The study examines 3,284 test-passing (resolved) patches from 11 public agent configurations on
SWE-bench Verified (2024–2026), alongside developers' fixes for the same issues. It records what each
patch removed (guard clauses; validation, escaping, or permission calls; error handling; test
assertions), what risky operations it added, and whether tests, scanners (Bandit, Semgrep), or the
leaderboard reported any of it. All patches are public leaderboard artifacts; no new patches were
generated.

## Contents

| Path | What it is |
|---|---|
| `notebook/PATCH_study.ipynb` | Full pipeline for Google Colab (CPU only): download patches, analyze, scan, triage, seeded deletions, labeling, detector-miss check. |
| `src/patchstudy.py` | Analysis library: function-level removal and addition detection, patch application, scanner diffing, triage, statistics. |
| `src/final_analysis.py` | Produces the paper's numbers, Table 2 rows, and figure data from `data/triage.jsonl`. |
| `data/` | Per-patch results and labels. |
| `labeling/labeling_guide.md` | The guide given to every labeler, including the AI comparison labeler. |
| `paper/main.tex` | Article source (self-contained; compiles with IEEEtran). |

## Reproduce

**Paper numbers only (seconds):**
```bash
pip install pandas numpy matplotlib
TRIAGE=data/triage.jsonl OUT=out python src/final_analysis.py
```

**Full pipeline (about 2–3 hours on a standard Colab CPU runtime):** open
`notebook/PATCH_study.ipynb` in Colab and run the cells in order. Set `QUICK_TEST = True` first for
an end-to-end check in about 10 minutes. Sections 19 (labeling) and 20 (detector-miss check) reload
everything from Google Drive and can be run in a later session.

## Method summary

- **Cohorts:** five agent designs on Claude 3.5 Sonnet (2024), and mini-SWE-agent with six models
  (2025–2026). Two entries with under 90% of resolved patches retrievable were excluded
  (Claude Sonnet 4, 35%; Kimi K2.5, 28%).
- **Baseline:** developers' fixes, compared on exactly the issues each configuration resolved;
  intervals from resampling whole issues.
- **Scanners:** Bandit and Semgrep (`p/python`, `p/security-audit`, plus local rules) on every changed
  production file before and after; new findings of medium or higher severity.
- **Labels:** two author-labelers, blind to source, working independently from
  `labeling/labeling_guide.md`.

## License

Code: MIT (see `LICENSE`). Data derived from SWE-bench leaderboard artifacts remain subject to the
terms of their sources.
