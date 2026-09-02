# Firewall Rule Audit & Migration Mapper

A Python toolkit that audits a firewall rule base for risk (overly permissive rules, unused rules, shadowed duplicates, logging gaps) and generates a clean, migration-ready rule set for a target vendor platform.

Built to reflect real firewall separation/migration work — reviewing large rule bases and migrating traffic to a new platform without carrying forward years of unreviewed rule sprawl.

## Why this exists

Enterprise firewall rule bases accumulate cruft over years: rules nobody remembers the purpose of, duplicate entries that silently shadow each other, and "temporary" any/any rules that never got tightened. Before any migration or platform separation, that rule base needs to be audited — not just copied over as-is.

This toolkit automates the two hardest parts of that process:
1. **Finding what's actually safe to drop** (zero-hit rules, shadowed duplicates)
2. **Flagging what a human needs to review** (overly permissive rules, missing logging) — instead of auto-deciding on things the tool doesn't have context for

## Features

- **Audit engine** — flags overly permissive (`any/any`) allow rules, zero-hit unused rules, duplicate/shadowed rules, and allow rules with logging disabled
- **Vendor migration mapper** — converts a normalized rule set into deployable syntax for Check Point, Palo Alto, or Cisco ASA
- **Clean migration set builder** — automatically excludes unused and shadowed rules from the migration output, while leaving permissive-rule decisions to a human reviewer
- **Auto-generated audit report** (Markdown) and **migration-ready rule file** for the target platform

## Quick start

```bash
git clone https://github.com/<your-username>/firewall-rule-audit.git
cd firewall-rule-audit

cd src
python3 run_audit.py
```

This parses the included sample rule export (`sample_data/legacy_rules_asa.csv` — a mock Cisco ASA-style rule base, no real firewall access needed), runs the full audit, and writes:

- `reports/audit_report.md` — human-readable findings
- `reports/migration_checkpoint.txt` — clean, migration-ready Check Point rule syntax

### Run individual components

```bash
python3 audit_engine.py     # just print the audit findings to console
```

```python
# Convert to a different target vendor
from rule_parser import parse_csv
from vendor_mapper import convert

rules = parse_csv("../sample_data/legacy_rules_asa.csv")
print(convert(rules, "paloalto"))   # or "checkpoint", "cisco_asa"
```

## Sample findings (against the included sample data)

```
🚨 OVERLY PERMISSIVE RULES: 3
   LEGACY-ANY-ANY           any -> any  svc=any/any  action=allow  hits=342
   WIDE-OPEN-TEST-RULE      10.0.0.0/8 -> 10.0.0.0/8  svc=any/any  action=allow  hits=55

🗑  UNUSED RULES (0 hits): 4
   OLD-VPN-RULE-1           192.168.50.0/24 -> 10.30.0.0/16  svc=tcp/1723

♻  DUPLICATE / SHADOWED RULES: 2 duplicate group(s)
   ALLOW-HTTPS-DMZ-DUP will never match (shadowed by ALLOW-WEB-DMZ)

Migration Summary: 8 of 12 rules carried forward, 4 excluded (unused/shadowed)
```

Full methodology and design trade-offs — including *why* deny rules are excluded from the "overly permissive" check, and why hit count matters more than rule age — are in [`docs/design-notes.md`](docs/design-notes.md).

## Project structure

```
firewall-rule-audit/
├── src/
│   ├── rule_parser.py      # normalizes rule exports (CSV/JSON) into a common format
│   ├── audit_engine.py     # runs all audit checks
│   ├── vendor_mapper.py    # converts rules to Check Point / Palo Alto / ASA syntax
│   └── run_audit.py        # combined workflow: audit -> clean set -> migration output
├── sample_data/
│   └── legacy_rules_asa.csv
├── reports/                 # generated audit reports and migration output land here
├── docs/
│   └── design-notes.md
└── requirements.txt
```

## Roadmap / possible extensions

- [ ] Direct integration with Check Point Management API (`mgmt_cli`) and Palo Alto XML API for live rule pulls instead of CSV export
- [ ] Object/group resolution (expand named objects to actual IP ranges before analysis)
- [ ] Rule overlap detection beyond exact duplicates (e.g., a broader rule that partially shadows a narrower one)
- [ ] CSV/Excel export of the audit report for non-technical stakeholders
- [ ] Historical hit-count trending (flag rules that *used* to be active but have gone cold recently)

## Background

Built by a network engineer with hands-on experience running a firewall rule-base separation project — reviewing large volumes of firewall logs and migrating traffic to new Check Point firewalls as part of a company divestiture.
