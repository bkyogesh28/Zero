import os
import yaml
from typing import Any, Optional


RULES_DIR = "rules"


def load_rules():
    rules = []
    for filename in os.listdir(RULES_DIR):
        if filename.endswith((".yml", ".yaml")):
            with open(os.path.join(RULES_DIR, filename), "r", encoding="utf-8") as f:
                rules.append(yaml.safe_load(f))
    return rules


def _match_field(event_value: Any, rule_value: Any, modifier: Optional[str] = None) -> bool:
    if event_value is None:
        return False

    event_str = str(event_value).lower()

    if modifier == "contains":
        if isinstance(rule_value, list):
            return any(str(v).lower() in event_str for v in rule_value)
        return str(rule_value).lower() in event_str

    if isinstance(rule_value, list):
        return event_str in [str(v).lower() for v in rule_value]

    return event_str == str(rule_value).lower()


def _match_selection(selection: dict, event: dict) -> bool:
    for field_expr, expected in selection.items():
        if "|contains" in field_expr:
            field = field_expr.split("|", 1)[0]
            if not _match_field(event.get(field), expected, modifier="contains"):
                return False
        else:
            if not _match_field(event.get(field_expr), expected):
                return False
    return True


def evaluate_rule(rule: dict, event: dict) -> bool:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "").strip()

    matched = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        matched[key] = _match_selection(value, event)

    if " and " in condition:
        parts = [p.strip() for p in condition.split(" and ")]
        return all(matched.get(p, False) for p in parts)

    if " or " in condition:
        parts = [p.strip() for p in condition.split(" or ")]
        return any(matched.get(p, False) for p in parts)

    return matched.get(condition, False)


def run_sigma(event: dict):
    alerts = []
    for rule in load_rules():
        if evaluate_rule(rule, event):
            alerts.append({
                "rule_id": rule.get("id"),
                "title": rule.get("title"),
                "severity": rule.get("level", "medium"),
                "description": rule.get("description"),
                "tags": rule.get("tags", []),
            })
    return alerts
