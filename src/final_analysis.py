# Final analysis for "What Did Your AI Patch Remove?"
# Reads triage.jsonl (written by cell 11 of the notebook) and writes results_macros.tex,
# table_results_rows.tex and fig_results.pdf. In Colab, run as the last cell with T, RESOLVED,
# SUBMISSIONS in memory, or standalone with the RESOLVED_COUNTS below (from cell 5's output).
import json, math, os, collections
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

TRIAGE = os.environ.get("TRIAGE", "triage.jsonl")
OUT = os.environ.get("OUT", "out"); os.makedirs(OUT, exist_ok=True)
MIN_COVERAGE = 0.90   # rule fixed before looking at per-configuration results: >= 90% of resolved patches analyzed

CONFIGS = {  # key: (label, cohort, date, resolved ids listed by the leaderboard)
  '20240620_sweagent_claude3.5sonnet':                      ('SWE-agent',        'scaffold', '2024-06', 168),
  '20241022_tools_claude-3-5-sonnet-updated':               ('Minimal tools',    'scaffold', '2024-10', 245),
  '20241029_OpenHands-CodeAct-2.1-sonnet-20241022':         ('OpenHands',        'scaffold', '2024-10', 265),
  '20241108_autocoderover-v2.0-claude-3-5-sonnet-20241022': ('AutoCodeRover',    'scaffold', '2024-11', 231),
  '20241202_agentless-1.5_claude-3.5-sonnet-20241022':      ('Agentless',        'scaffold', '2024-12', 254),
  '20250726_mini-v1.0.0_claude-sonnet-4-20250514':          ('Claude Sonnet 4',  'model', '2025-05', 324),
  '20250807_mini-v1.7.0_gpt-5':                             ('GPT-5',            'model', '2025-08', 325),
  '20251124_mini-v1.16.0_claude-opus-4-5-20251101':         ('Claude Opus 4.5',  'model', '2025-11', 372),
  '20260217_mini-v2.0.0_gpt-5-2-high':                      ('GPT-5.2',          'model', '2025-12', 364),
  '20260217_mini-v2.0.0_kimi-k2-5-high':                    ('Kimi K2.5',        'model', '2026-01', 354),
  '20260217_mini-v2.0.0_claude-4-6-opus':                   ('Claude Opus 4.6',  'model', '2026-02', 378),
  '20260217_mini-v2.0.0_glm-5-high':                        ('GLM-5',            'model', '2026-02', 364),
  '20260901_mini-v2.4.2_gemini-3-5-flash':                  ('Gemini 3.5 Flash', 'model', '2026-05', 359),
}
REMOVAL = {'A:guard-removed', 'A:validation-removed', 'A:errors-silenced', 'T:test-assertions-removed'}
ADDITION = {'A:new-dangerous-operation'}

def wilson(k, n, z=1.96):
    if n == 0: return (float('nan'),) * 3
    p = k / n; d = 1 + z*z/n; c = (p + z*z/(2*n)) / d
    h = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return p, max(0, c-h), min(1, c+h)

def mcnemar_exact(b, c):
    n = b + c
    if n == 0: return 1.0
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2**n)

T = pd.read_json(TRIAGE, lines=True)
T['removal'] = T.reasons.apply(lambda r: bool(REMOVAL & set(r)))
T['addition'] = T.reasons.apply(lambda r: bool(ADDITION & set(r)))
real = T[~T.submission.str.startswith('seed:')]
seed = T[T.submission.str.startswith('seed:')]

cov = {k: (real.submission == k).sum() / v[3] for k, v in CONFIGS.items()}
KEEP = [k for k in CONFIGS if cov[k] >= MIN_COVERAGE]
EXCL = [k for k in CONFIGS if k not in KEEP]
print('coverage:', {CONFIGS[k][0]: round(v, 2) for k, v in cov.items()})
print('excluded (<90% coverage):', [CONFIGS[k][0] for k in EXCL])

ag = real[real.submission.isin(KEEP)]
dev = real[real.submission == 'gold']
both = pd.concat([ag, dev])

rows = []
for k in ['gold'] + KEEP:
    d = dev if k == 'gold' else ag[ag.submission == k]
    lab, coh, date = ('Developer fixes', 'baseline', '--') if k == 'gold' else CONFIGS[k][:3]
    p, lo, hi = wilson(int((d.outcome == 'HOLD').sum()), len(d))
    rows.append(dict(key=k, label=lab, cohort=coh, date=date, n=len(d), hold=100*p, lo=100*lo, hi=100*hi,
                     removal=100*d.removal.mean(), addition=100*d.addition.mean(), stray=100*d.stray.mean()))
TAB = pd.DataFrame(rows)
print(TAB.round(1).to_string(index=False))
TAB.to_csv(os.path.join(OUT, 'tab.csv'), index=False)

# paired: held (any A or T signal) by agent vs developer on the same issue
g = (dev.set_index('instance_id').outcome == 'HOLD').rename('dev_hold')
m = ag.join(g, on='instance_id'); a = m.outcome == 'HOLD'
pair_ao, pair_do = int((a & ~m.dev_hold).sum()), int((~a & m.dev_hold).sum())
pair_p = mcnemar_exact(pair_ao, pair_do)
gr = dev.set_index('instance_id').removal.rename('dev_rem')
m2 = ag.join(gr, on='instance_id')
rem_ao, rem_do = int((m2.removal & ~m2.dev_rem).sum()), int((~m2.removal & m2.dev_rem).sum())

n_rem, n_rem_scan = int(both.removal.sum()), int((both.removal & both.scanner).sum())
n_add, n_add_scan = int(both.addition.sum()), int((both.addition & both.scanner).sum())
kinds = {k: int(both.reasons.apply(lambda r: k in r).sum()) for k in sorted(REMOVAL)}
silenced_ag = int(ag.reasons.apply(lambda r: 'A:errors-silenced' in r).sum())
silenced_dev = int(dev.reasons.apply(lambda r: 'A:errors-silenced' in r).sum())
tests_ag = int(ag.reasons.apply(lambda r: 'T:test-assertions-removed' in r).sum())
scaffold = ag[ag.submission.isin([k for k in KEEP if CONFIGS[k][1] == 'scaffold'])]
model = ag[ag.submission.isin([k for k in KEEP if CONFIGS[k][1] == 'model'])]
print(dict(n_rem=n_rem, n_rem_scan=n_rem_scan, n_add=n_add, n_add_scan=n_add_scan, kinds=kinds,
           pair=(pair_ao, pair_do, pair_p), rem_pair=(rem_ao, rem_do), silenced=(silenced_ag, silenced_dev), tests_ag=tests_ag))

# ------------------------------------------------------------------ figure
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 8})
fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.0), gridspec_kw=dict(width_ratios=[1.25, 1]))
ax = axes[0]
o = TAB[TAB.key != 'gold'].reset_index(drop=True); y = np.arange(len(o))[::-1]
ax.barh(y, o.hold, color=['#306A9E' if c == 'scaffold' else '#A86108' for c in o.cohort], height=0.62)
ax.errorbar(o.hold, y, xerr=[o.hold - o.lo, o.hi - o.hold], fmt='none', ecolor='#18212E', lw=0.7, capsize=1.5)
dh = TAB[TAB.key == 'gold'].iloc[0]
ax.axvspan(dh.lo, dh.hi, color='#21643C', alpha=0.10, lw=0)
ax.axvline(dh.hold, color='#21643C', ls='--', lw=1)
ax.text(dh.hi + 0.3, -0.95, 'developer fixes (95% CI)', color='#21643C', fontsize=6.8, va='center')
ax.set_ylim(-1.35, len(o) - 0.4); ax.set_yticks(y); ax.set_yticklabels(o.label)
ax.set_xlabel('Resolved patches held for review (%)')
ax.set_title('(a) Held by PATCH triage, by configuration', loc='left', fontsize=8, fontweight='bold')
for s in ('top', 'right'): ax.spines[s].set_visible(False)
ax = axes[1]
lab = [f'Added a risky\noperation\n(real, n={n_add})', f'Removed a\nprotection\n(real, n={n_rem})', f'Deleted a\nprotection\n(seeded, n={len(seed)})']
val = [100*n_add_scan/max(1, n_add), 100*n_rem_scan/max(1, n_rem), 100*seed.scanner.mean()]
bars = ax.bar(range(3), val, color=['#795DA1', '#A63238', '#A63238'], width=0.58)
bars[2].set_hatch('///'); bars[2].set_edgecolor('white')
for b, v in zip(bars, val):
    ax.text(b.get_x() + b.get_width()/2, v + 2, f'{v:.0f}%', ha='center', va='bottom', fontsize=8, fontweight='bold')
ax.set_xticks(range(3)); ax.set_xticklabels(lab, fontsize=7); ax.set_ylim(0, 100)
ax.set_ylabel('Flagged by Bandit or Semgrep (%)')
ax.set_title('(b) What the scanners saw', loc='left', fontsize=8, fontweight='bold')
for s in ('top', 'right'): ax.spines[s].set_visible(False)
fig.tight_layout(); fig.savefig(os.path.join(OUT, 'fig_results.pdf'), bbox_inches='tight')
fig.savefig(os.path.join(OUT, 'fig_results.png'), dpi=160, bbox_inches='tight')

# ------------------------------------------------------------------ LaTeX outputs
f0 = lambda v: f'{v:.0f}'; f1 = lambda v: f'{v:.1f}'
agt = TAB[TAB.key != 'gold']
M = {
 'NConfigs': len(KEEP), 'NExcluded': len(EXCL), 'NResolved': len(ag), 'NIssues': ag.instance_id.nunique(), 'NDev': len(dev),
 'HoldPooled': f1(100*(ag.outcome == 'HOLD').mean()), 'HoldMin': f1(agt.hold.min()), 'HoldMax': f1(agt.hold.max()),
 'HoldModelMax': f1(agt[agt.cohort == 'model'].hold.max()), 'HoldDev': f1(dh.hold),
 'RemAgents': f1(100*ag.removal.mean()), 'RemDev': f1(100*dev.removal.mean()),
 'PairAgentOnly': pair_ao, 'PairDevOnly': pair_do, 'PairP': f'{pair_p:.2f}',
 'RemPairAgentOnly': rem_ao, 'RemPairDevOnly': rem_do,
 'NRem': n_rem, 'RemScan': n_rem_scan, 'RemScanPct': f0(100*n_rem_scan/max(1, n_rem)),
 'NAdd': n_add, 'AddScan': n_add_scan, 'AddScanPct': f0(100*n_add_scan/max(1, n_add)),
 'NRemDev': int(dev.removal.sum()), 'NRemAgents': int(ag.removal.sum()),
 'NGuard': kinds['A:guard-removed'], 'NValid': kinds['A:validation-removed'], 'NSilenced': kinds['A:errors-silenced'],
 'NTests': kinds['T:test-assertions-removed'], 'SilencedAgents': silenced_ag, 'SilencedDev': silenced_dev, 'TestsAgents': tests_ag,
 'StrayScaffold': f0(100*scaffold.stray.mean()), 'StrayModel': f1(100*model.stray.mean()),
 'StrayMax': f0(agt.stray.max()),
 'ScopeOnly': f0(100*(ag.outcome == 'SCOPE').mean()), 'ScanDev': f1(100*dev.scanner.mean()),
 'SeedFlagged': int(seed.scanner.sum()),
 'SeedFlaggedFromFix': int(dev.set_index('instance_id').scanner.reindex(seed[seed.scanner].instance_id).fillna(False).sum()),
 'SeedN': len(seed), 'SeedScanner': f0(100*seed.scanner.mean()), 'SeedPatch': f0(100*(seed.outcome == 'HOLD').mean()),
}
with open(os.path.join(OUT, 'results_macros.tex'), 'w') as fh:
    fh.write('% Generated by final_analysis.py. Do not edit by hand.\n')
    for k, v in M.items():
        fh.write(f'\\renewcommand{{\\{k}}}{{{v}}}\n')
with open(os.path.join(OUT, 'table_results_rows.tex'), 'w') as fh:
    prev = None
    for r in TAB.itertuples():
        if prev is not None and r.cohort != prev: fh.write('\\hline\n')
        name = '\\textit{Developer fixes}' if r.key == 'gold' else r.label
        fh.write(f'{name} & {r.date} & {r.n} & {r.hold:.1f} ({r.lo:.1f}--{r.hi:.1f}) & {r.removal:.1f} & {r.addition:.1f} & {r.stray:.0f} \\\\\n')
        prev = r.cohort
print(open(os.path.join(OUT, 'results_macros.tex')).read())
