# Data

| File | Rows | Contents |
|---|---|---|
| `triage.jsonl` | one per analyzed patch | Per-patch results: `submission` (leaderboard entry; `gold` = developer fix; `seed:<type>` = seeded patch), `instance_id`, `outcome` (HOLD / SCOPE / PROCEED), `reasons` (signals), removal and addition details, new scanner findings, stray-file and scope flags. |
| `removal_labels_resolved.csv` | 97 | Final human labels for every removal patch, with its source (agent entry or `gold`) and whether a scanner flagged it. |

## Add before publishing (from `MyDrive/patch_study/`)

- `removal_labels_A1.csv`, `removal_labels_A2.csv`, `removal_labels_final.csv` (independent and final labels)
- `removal_labels_AI.csv` (Claude Sonnet 5.5 comparison labels)
- `removal_labels_A3.csv` and `misscheck_results.csv`, if those steps were run
- `removal_label_key.csv` (maps blinded item numbers to patches)
- `seeded.json` (the 832 seeded patches) and `records.jsonl` (raw per-patch records)

`patches.json` (the agents' patches) can be regenerated from the public SWE-bench leaderboard
artifacts with notebook cell 6, so it need not be committed if it is large.
