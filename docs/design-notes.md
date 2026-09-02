# Design Notes

## Why exclude unused/shadowed rules automatically, but not overly permissive ones?

Zero-hit rules and shadowed duplicates are objectively safe to drop — by definition, no live traffic depends on them (a shadowed rule can *never* match, since an earlier identical rule always catches the traffic first). Automating their removal is low-risk and saves significant manual review time on a large rule base.

Overly permissive rules (`any/any`, wide service ranges) are different: they might genuinely be needed (e.g., a broad DMZ rule that's intentionally wide), or they might be forgotten cruft. That's a judgment call that depends on business context this tool doesn't have — so the audit **flags** them for a human decision rather than silently dropping or "fixing" them. Auto-tightening a rule without knowing what traffic depends on it is how you cause an outage during a migration window.

## Why hit count matters more than rule age

A rule created five years ago that's still getting hit thousands of times a day is doing real work. A rule created last month with zero hits might just not have been exercised yet, or might be dead on arrival. Hit count (pulled from the firewall's own counters) is a much more reliable signal than "how old is this rule" for deciding what's safe to retire — which is why this tool leads with hit count rather than rule creation date.

## Why deny rules are excluded from the "overly permissive" check

A broad `deny any any` rule at the bottom of a rule base is standard security practice (implicit or explicit default-deny), not a finding. Only **allow** rules with `any/any` or `any` service scope represent actual exposure, so the audit only flags those.

## Migration workflow assumption

This tool assumes a **rule-base cleanup pass before migration** — audit first, review overly-permissive flags with a human, then generate the clean migration set. That mirrors how a real firewall separation project should run: you don't want to carry forward a decade of unreviewed rule sprawl onto new hardware just because the old rule base "worked."

## Extending to real exports

Real firewall platforms don't export CSV by default:
- **Check Point**: use `mgmt_cli show-access-rulebase` (R80+ Management API) and transform the JSON output into the same field names used here
- **Palo Alto**: `show running security-policy` or the XML API (`/api/?type=config&action=get&xpath=...`) can be parsed similarly
- **Cisco ASA**: `show access-list` output can be parsed with a regex-based extractor into the same `Rule` fields

The `rule_parser.py` module is intentionally kept separate from the audit/mapping logic specifically so a new source format only requires adding one new `parse_*` function — nothing else changes.
