"""
vendor_mapper.py

Converts normalized Rule objects into deployable CLI/config syntax for a
target firewall vendor. This is the core of a real "firewall separation /
migration" project: you don't hand-retype hundreds of rules on the new
platform, you programmatically translate them.

Supported targets:
  - Check Point (dbedit-style / clish-style representation)
  - Palo Alto (`set` CLI syntax)
  - Cisco ASA (access-list syntax) -- included as a reference/reverse case

Only ALLOW rules that are NOT flagged for removal should typically be
migrated -- pair this with audit_engine.py findings before generating
final migration output (see run_audit.py for the combined workflow).
"""

from typing import List
from rule_parser import Rule


def to_checkpoint(rules: List[Rule]) -> str:
    lines = ["# Check Point rule migration - clish-style representation",
             "# Import via SmartConsole or dbedit as appropriate for your version", ""]
    for r in rules:
        action = "accept" if r.action == "allow" else "drop"
        service = "any" if r.is_any_service else f"{r.service}_{r.port}"
        lines.append(
            f'add_rule name="{r.rule_name}" source="{r.source}" '
            f'destination="{r.destination}" service="{service}" '
            f'action="{action}" track="{"Log" if r.log_enabled else "None"}"'
        )
    return "\n".join(lines)


def to_paloalto(rules: List[Rule]) -> str:
    lines = ["# Palo Alto Networks - set-format CLI commands",
             "# Apply via CLI configure mode or import as a named rulebase", ""]
    for r in rules:
        action = "allow" if r.action == "allow" else "deny"
        service = "any" if r.is_any_service else f"service-{r.service}-{r.port}"
        lines.append(f"set rulebase security rules {r.rule_name} from any to any "
                     f"source {r.source} destination {r.destination} "
                     f"application any service {service} action {action}")
        if r.log_enabled:
            lines.append(f"set rulebase security rules {r.rule_name} log-end yes")
    return "\n".join(lines)


def to_cisco_asa(rules: List[Rule]) -> str:
    lines = ["! Cisco ASA access-list syntax", ""]
    for r in rules:
        action = "permit" if r.action == "allow" else "deny"
        proto = r.service if r.service.lower() != "any" else "ip"
        port_clause = f"eq {r.port}" if r.port.lower() not in ("any",) and proto in ("tcp", "udp") else ""
        lines.append(
            f"access-list MIGRATED-ACL extended {action} {proto} "
            f"{r.source} {r.destination} {port_clause}".strip()
        )
        if r.log_enabled:
            lines[-1] += " log"
    return "\n".join(lines)


VENDOR_MAP = {
    "checkpoint": to_checkpoint,
    "paloalto": to_paloalto,
    "cisco_asa": to_cisco_asa,
}


def convert(rules: List[Rule], target_vendor: str) -> str:
    if target_vendor not in VENDOR_MAP:
        raise ValueError(f"Unsupported target vendor '{target_vendor}'. "
                          f"Choose from: {list(VENDOR_MAP.keys())}")
    return VENDOR_MAP[target_vendor](rules)
