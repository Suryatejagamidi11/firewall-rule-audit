"""
audit_engine.py

Runs a set of checks against a parsed rule list:

  1. Overly permissive rules (any-source AND any-destination, or any-service)
  2. Unused rules (zero hit count) -- candidates for removal
  3. Duplicate / shadowed rules -- rules that are functionally identical to
     an earlier rule, meaning the later one can never actually match traffic
  4. Rules with logging disabled on an allow action (visibility gap)

This is the kind of audit that matters most before a firewall migration --
you don't want to carry 10 years of rule sprawl, unused legacy rules, and
duplicate entries onto a brand-new platform. Clean the rule base first,
then migrate only what's actually needed.
"""

from typing import List, Dict, Any
from collections import defaultdict
from rule_parser import Rule


def find_overly_permissive(rules: List[Rule]) -> List[Rule]:
    # Only flag ALLOW rules -- a broad "deny any-any" catch-all rule is a
    # legitimate, common security best practice, not a finding.
    return [r for r in rules if not r.disabled and r.action == "allow"
            and (r.is_any_any or r.is_any_service)]


def find_unused(rules: List[Rule], min_hits: int = 1) -> List[Rule]:
    return [r for r in rules if not r.disabled and r.hit_count < min_hits]


def find_duplicates(rules: List[Rule]) -> List[Dict[str, Any]]:
    seen = defaultdict(list)
    for r in rules:
        seen[r.identity_key()].append(r)

    duplicates = []
    for key, group in seen.items():
        if len(group) > 1:
            duplicates.append({
                "match": key,
                "rules": group,
                "shadowed": group[1:],  # everything after the first is unreachable
            })
    return duplicates


def find_unlogged_allows(rules: List[Rule]) -> List[Rule]:
    return [r for r in rules if not r.disabled and r.action == "allow" and not r.log_enabled]


def run_full_audit(rules: List[Rule]) -> Dict[str, Any]:
    return {
        "total_rules": len(rules),
        "overly_permissive": find_overly_permissive(rules),
        "unused": find_unused(rules),
        "duplicates": find_duplicates(rules),
        "unlogged_allows": find_unlogged_allows(rules),
    }


def print_audit_report(audit: Dict[str, Any]) -> None:
    print("=" * 72)
    print("FIREWALL RULE AUDIT REPORT")
    print("=" * 72)
    print(f"Total rules analyzed: {audit['total_rules']}\n")

    print(f"🚨 OVERLY PERMISSIVE RULES: {len(audit['overly_permissive'])}")
    for r in audit["overly_permissive"]:
        print(f"   {r.rule_name:<24} {r.source} -> {r.destination}  "
              f"svc={r.service}/{r.port}  action={r.action}  hits={r.hit_count}")

    print(f"\n🗑  UNUSED RULES (0 hits, candidates for removal): {len(audit['unused'])}")
    for r in audit["unused"]:
        print(f"   {r.rule_name:<24} {r.source} -> {r.destination}  "
              f"svc={r.service}/{r.port}  action={r.action}")

    print(f"\n♻  DUPLICATE / SHADOWED RULES: {len(audit['duplicates'])} duplicate group(s)")
    for dup in audit["duplicates"]:
        names = [r.rule_name for r in dup["rules"]]
        shadowed_names = [r.rule_name for r in dup["shadowed"]]
        print(f"   Match group: {names} -- {shadowed_names} will never match "
              f"(shadowed by {dup['rules'][0].rule_name})")

    print(f"\n👁  ALLOW RULES WITH LOGGING DISABLED: {len(audit['unlogged_allows'])}")
    for r in audit["unlogged_allows"]:
        print(f"   {r.rule_name:<24} {r.source} -> {r.destination}  (no visibility into this traffic)")

    print()


if __name__ == "__main__":
    from rule_parser import parse_csv
    rules = parse_csv("../sample_data/legacy_rules_asa.csv")
    audit = run_full_audit(rules)
    print_audit_report(audit)
