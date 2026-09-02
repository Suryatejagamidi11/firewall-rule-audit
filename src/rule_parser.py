"""
rule_parser.py

Parses firewall rule exports into a common, vendor-agnostic Rule format
so the audit engine and vendor mapper don't need to know anything about
the source format.

Currently supports CSV exports (the common denominator most firewall
management consoles -- Check Point SmartConsole, Panorama, ASDM -- can
export to). JSON support is included as a second example format.

Extending this to a real vendor's native export format (e.g. Check Point
.W or Palo Alto XML config) just means adding another `parse_*` function
that returns the same Rule objects -- nothing downstream needs to change.
"""

import csv
import json
from dataclasses import dataclass, field
from typing import List


@dataclass
class Rule:
    rule_name: str
    source: str
    destination: str
    service: str
    port: str
    action: str
    hit_count: int = 0
    disabled: bool = False
    log_enabled: bool = True
    vendor: str = "unknown"

    @property
    def is_any_any(self) -> bool:
        return self.source.strip().lower() == "any" and self.destination.strip().lower() == "any"

    @property
    def is_any_service(self) -> bool:
        return self.service.strip().lower() == "any" or self.port.strip().lower() == "any"

    def identity_key(self) -> tuple:
        """
        Used to detect duplicate/shadowed rules: two rules with the same
        source, destination, service, port, and action are functionally
        identical from a traffic-matching standpoint, regardless of name.
        """
        return (
            self.source.strip().lower(),
            self.destination.strip().lower(),
            self.service.strip().lower(),
            self.port.strip().lower(),
            self.action.strip().lower(),
        )


def parse_csv(path: str) -> List[Rule]:
    rules = []
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(Rule(
                rule_name=row["rule_name"],
                source=row["source"],
                destination=row["destination"],
                service=row["service"],
                port=row["port"],
                action=row["action"],
                hit_count=int(row.get("hit_count", 0) or 0),
                disabled=str(row.get("disabled", "false")).strip().lower() == "true",
                log_enabled=str(row.get("log_enabled", "true")).strip().lower() == "true",
                vendor=row.get("vendor", "unknown"),
            ))
    return rules


def parse_json(path: str) -> List[Rule]:
    with open(path, "r") as f:
        data = json.load(f)
    rules = []
    for row in data:
        rules.append(Rule(
            rule_name=row["rule_name"],
            source=row["source"],
            destination=row["destination"],
            service=row["service"],
            port=str(row.get("port", "any")),
            action=row["action"],
            hit_count=int(row.get("hit_count", 0) or 0),
            disabled=bool(row.get("disabled", False)),
            log_enabled=bool(row.get("log_enabled", True)),
            vendor=row.get("vendor", "unknown"),
        ))
    return rules
