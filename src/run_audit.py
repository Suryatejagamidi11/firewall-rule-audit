"""
run_audit.py

Combined workflow that mirrors a real firewall separation/migration project:

  1. Parse the legacy rule export
  2. Run the audit (permissive rules, unused rules, duplicates/shadows, logging gaps)
  3. Build a "clean" migration set -- excluding unused and shadowed rules --
     so you migrate only what's actually needed onto the new platform
  4. Generate:
       - reports/audit_report.md   (human-readable findings)
       - reports/migration_checkpoint.txt  (ready-to-review Check Point rules)

Usage:
    python run_audit.py
"""

from pathlib import Path
from datetime import datetime

from rule_parser import parse_csv
from audit_engine import run_full_audit
from vendor_mapper import convert


def build_clean_migration_set(rules, audit):
    """
    Rules to exclude from migration:
      - Zero-hit / unused rules
      - Shadowed duplicates (the later, unreachable copy)

    Everything else migrates forward. Overly permissive rules are flagged
    in the audit but NOT auto-excluded -- those need a human decision
    (tighten the rule vs. accept the risk), not an automatic drop.
    """
    unused_names = {r.rule_name for r in audit["unused"]}
    shadowed_names = {r.rule_name for dup in audit["duplicates"] for r in dup["shadowed"]}
    exclude = unused_names | shadowed_names

    clean = [r for r in rules if r.rule_name not in exclude]
    excluded = [r for r in rules if r.rule_name in exclude]
    return clean, excluded


def write_audit_markdown(audit, excluded_rules, output_path):
    lines = []
    lines.append("# Firewall Rule Audit Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ")
    lines.append(f"**Total rules analyzed:** {audit['total_rules']}  ")
    lines.append("")

    lines.append(f"## 🚨 Overly Permissive Rules ({len(audit['overly_permissive'])})")
    lines.append("These need a human decision before migration -- tighten scope or accept the risk.")
    lines.append("")
    if audit["overly_permissive"]:
        lines.append("| Rule | Source | Destination | Service | Hits |")
        lines.append("|---|---|---|---|---|")
        for r in audit["overly_permissive"]:
            lines.append(f"| {r.rule_name} | {r.source} | {r.destination} | "
                          f"{r.service}/{r.port} | {r.hit_count} |")
    else:
        lines.append("None found.")
    lines.append("")

    lines.append(f"## 🗑 Unused Rules -- excluded from migration ({len(audit['unused'])})")
    lines.append("")
    if audit["unused"]:
        for r in audit["unused"]:
            lines.append(f"- `{r.rule_name}` — {r.source} → {r.destination} "
                          f"({r.service}/{r.port}) — 0 hits recorded")
    else:
        lines.append("None found.")
    lines.append("")

    lines.append(f"## ♻ Duplicate / Shadowed Rules -- excluded from migration ({len(audit['duplicates'])} group(s))")
    lines.append("")
    if audit["duplicates"]:
        for dup in audit["duplicates"]:
            kept = dup["rules"][0].rule_name
            shadowed = ", ".join(r.rule_name for r in dup["shadowed"])
            lines.append(f"- Kept `{kept}`, dropped shadowed duplicate(s): {shadowed}")
    else:
        lines.append("None found.")
    lines.append("")

    lines.append(f"## 👁 Allow Rules With Logging Disabled ({len(audit['unlogged_allows'])})")
    lines.append("")
    if audit["unlogged_allows"]:
        for r in audit["unlogged_allows"]:
            lines.append(f"- `{r.rule_name}` — {r.source} → {r.destination} (recommend enabling logging)")
    else:
        lines.append("None found.")
    lines.append("")

    lines.append("## Migration Summary")
    lines.append("")
    lines.append(f"- **{audit['total_rules'] - len(excluded_rules)} rules** carried forward to the new platform")
    lines.append(f"- **{len(excluded_rules)} rules** excluded (unused or shadowed duplicates)")
    lines.append("- Overly permissive rules were carried forward as-is; review before go-live")

    Path(output_path).write_text("\n".join(lines))
    print(f"Audit report written to: {output_path}")


def main():
    src_dir = Path(__file__).resolve().parent
    sample_path = src_dir.parent / "sample_data" / "legacy_rules_asa.csv"
    reports_dir = src_dir.parent / "reports"
    reports_dir.mkdir(exist_ok=True)

    rules = parse_csv(str(sample_path))
    audit = run_full_audit(rules)
    clean_rules, excluded_rules = build_clean_migration_set(rules, audit)

    write_audit_markdown(audit, excluded_rules, str(reports_dir / "audit_report.md"))

    checkpoint_output = convert(clean_rules, "checkpoint")
    (reports_dir / "migration_checkpoint.txt").write_text(checkpoint_output)
    print(f"Migration-ready Check Point rules written to: {reports_dir / 'migration_checkpoint.txt'}")

    print(f"\nSummary: {len(clean_rules)} rules migrating, "
          f"{len(excluded_rules)} excluded (unused/shadowed).")


if __name__ == "__main__":
    main()
