"""Render analysis results as text, JSON, or a self-contained HTML report."""
from __future__ import annotations

import json
from html import escape

from .analyzer import AnalysisResult
from .crack_time import CrackEstimate, estimate


def _bar(fraction: float, width: int = 30) -> str:
    filled = int(round(fraction * width))
    return "#" * filled + "-" * (width - filled)


def to_text(result: AnalysisResult) -> str:
    p = result.policy
    lines = []
    lines.append("=" * 60)
    lines.append("PASSWORD POLICY BREACH ANALYSIS")
    lines.append("=" * 60)
    lines.append(f"Policy: {p.describe()}")
    lines.append(f"Passwords examined: {result.total:,}")
    lines.append("")
    lines.append(
        f"Breach passwords ALLOWED by policy : {result.compliant:,} "
        f"({result.compliant_rate * 100:.2f}%)  [{_bar(result.compliant_rate)}]"
    )
    lines.append(
        f"Breach passwords BLOCKED by policy : {result.rejected:,} "
        f"({result.rejected_rate * 100:.2f}%)  [{_bar(result.rejected_rate)}]"
    )
    lines.append("")
    lines.append(
        "NOTE: 'allowed' passwords are real leaked passwords your policy does "
        "NOT stop. They are already in every attacker's dictionary, so they are "
        "effectively cracked instantly regardless of hash algorithm."
    )
    lines.append("")
    lines.append("Top reasons passwords were blocked:")
    for reason, count in result.failure_reasons.most_common(6):
        lines.append(f"  - {reason}: {count:,}")
    lines.append("")
    lines.append("Brute-force time for the WEAKEST password the policy allows:")
    lines.append(f"  (keyspace = {p.effective_charset_size()}^{p.min_length})")
    for est in estimate(p):
        lines.append(
            f"  {est.scenario:>3} / {est.algorithm:<7} "
            f"@ {est.hashrate:>10,.0f} H/s  ->  {est.pretty}"
        )
    lines.append("=" * 60)
    return "\n".join(lines)


def to_json(result: AnalysisResult) -> str:
    p = result.policy
    data = {
        "policy": p.to_dict(),
        "policy_description": p.describe(),
        "total_examined": result.total,
        "compliant": result.compliant,
        "rejected": result.rejected,
        "compliant_rate": result.compliant_rate,
        "rejected_rate": result.rejected_rate,
        "failure_reasons": dict(result.failure_reasons),
        "length_histogram": dict(sorted(result.length_hist.items())),
        "class_count_histogram": dict(sorted(result.class_count_hist.items())),
        "sample_compliant": result.sample_compliant,
        "bruteforce_estimates": [
            {
                "scenario": e.scenario,
                "algorithm": e.algorithm,
                "hashrate": e.hashrate,
                "keyspace": e.keyspace,
                "seconds": e.seconds,
                "pretty": e.pretty,
            }
            for e in estimate(p)
        ],
    }
    return json.dumps(data, indent=2)


def to_html(result: AnalysisResult) -> str:
    p = result.policy
    rows = "\n".join(
        f"<tr><td>{escape(e.scenario)}</td><td>{escape(e.algorithm)}</td>"
        f"<td>{e.hashrate:,.0f}</td><td>{escape(e.pretty)}</td></tr>"
        for e in estimate(p)
    )
    reasons = "\n".join(
        f"<li>{escape(r)}: {c:,}</li>" for r, c in result.failure_reasons.most_common(6)
    )
    samples = "\n".join(f"<li><code>{escape(s)}</code></li>" for s in result.sample_compliant)
    allowed_pct = result.compliant_rate * 100
    blocked_pct = result.rejected_rate * 100
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Password Policy Breach Analysis</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, sans-serif; max-width: 820px; margin: 2rem auto;
         padding: 0 1rem; line-height: 1.5; }}
  h1 {{ font-size: 1.5rem; }}
  .bar {{ background: #8883; border-radius: 6px; overflow: hidden; height: 1.4rem; }}
  .bar > span {{ display: block; height: 100%; }}
  .allowed {{ background: #e5534b; }}
  .blocked {{ background: #3fb950; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: .5rem; }}
  th, td {{ border: 1px solid #8884; padding: .3rem .5rem; text-align: left; }}
  code {{ background: #8882; padding: 0 .25rem; border-radius: 4px; }}
  .note {{ background: #f0ad4e22; border-left: 4px solid #f0ad4e; padding: .6rem 1rem; }}
</style>
</head>
<body>
<h1>Password Policy Breach Analysis</h1>
<p><strong>Policy:</strong> {escape(p.describe())}</p>
<p><strong>Passwords examined:</strong> {result.total:,}</p>

<h2>Breach passwords your policy would still allow</h2>
<p>{result.compliant:,} of {result.total:,} ({allowed_pct:.2f}%)</p>
<div class="bar"><span class="allowed" style="width:{allowed_pct:.2f}%"></span></div>
<p>Blocked: {result.rejected:,} ({blocked_pct:.2f}%)</p>
<div class="bar"><span class="blocked" style="width:{blocked_pct:.2f}%"></span></div>

<div class="note">
These "allowed" passwords are <strong>real leaked passwords</strong> your policy
does not stop. They already sit in every attacker's dictionary, so they are
cracked instantly no matter which hash algorithm you use. A good policy should
also reject known-breached passwords, not just enforce length and complexity.
</div>

<h2>Why passwords were blocked</h2>
<ul>{reasons}</ul>

<h2>Brute-force time for the weakest allowed password</h2>
<p>Keyspace = {p.effective_charset_size()}<sup>{p.min_length}</sup></p>
<table>
<tr><th>Hardware</th><th>Hash</th><th>Hashes/sec</th><th>Avg. crack time</th></tr>
{rows}
</table>

<h2>Sample of allowed breach passwords</h2>
<ul>{samples}</ul>

<footer><p><em>Generated by password-policy-breach-analyzer.</em></p></footer>
</body>
</html>"""
