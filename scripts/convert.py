
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified Rule Converter
Source: source/rules.list

Generated files:
  generated/clash-direct.list
  generated/clash-proxy.list
  generated/clash-reject.list
  generated/qx-direct.list
  generated/qx-proxy.list
  generated/qx-reject.list
  generated/karing-direct.json
  generated/karing-proxy.json
  generated/karing-reject.json

Important:
  - DST-PORT is retained for Clash.
  - DST-PORT is skipped for Quantumult X because its filter
    grammar does not support this rule type.
  - Karing port output uses the "port" field; verify that
    field against your installed Karing version before relying on it.
"""

from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILE = ROOT / "source" / "rules.list"
OUTPUT_DIR = ROOT / "generated"

SUPPORTED_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "DST-PORT",
}

SUPPORTED_POLICIES = {
    "DIRECT",
    "PROXY",
    "REJECT",
    "BLOCK",
}


def normalize_policy(policy):
    policy = policy.strip().upper()
    return "REJECT" if policy == "BLOCK" else policy


def parse_rule(line, line_number):
    parts = [part.strip() for part in line.split(",")]

    if len(parts) < 3:
        raise ValueError(
            f"Line {line_number}: invalid rule: {line}"
        )

    rule_type = parts[0].upper()
    value = parts[1]
    policy = normalize_policy(parts[2])
    options = parts[3:]

    if rule_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"Line {line_number}: unsupported rule type "
            f"{rule_type}: {line}"
        )

    if policy not in SUPPORTED_POLICIES:
        raise ValueError(
            f"Line {line_number}: unsupported policy "
            f"{policy}: {line}"
        )

    if not value:
        raise ValueError(
            f"Line {line_number}: rule value is empty"
        )

    if rule_type == "DST-PORT":
        try:
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError(
                f"Line {line_number}: invalid port: {value}"
            )

    return {
        "type": rule_type,
        "value": value,
        "policy": policy,
        "options": options,
        "line": line_number,
    }


def read_source():
    if not SOURCE_FILE.exists():
        raise FileNotFoundError(
            f"Source file not found: {SOURCE_FILE}"
        )

    rules = []
    seen = set()

    with SOURCE_FILE.open("r", encoding="utf-8-sig") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            rule = parse_rule(line, line_number)

            # Deduplicate equivalent rules.
            key = (
                rule["type"],
                rule["value"],
                rule["policy"],
                tuple(rule["options"]),
            )

            if key not in seen:
                seen.add(key)
                rules.append(rule)

    return rules


def unique_append(target, value):
    if value not in target:
        target.append(value)


def split_by_policy(rules, converter, client):
    result = {
        "DIRECT": [],
        "PROXY": [],
        "REJECT": [],
    }

    skipped = []

    for rule in rules:
        if client == "qx" and rule["type"] == "DST-PORT":
            skipped.append(rule)
            continue

        converted = converter(rule)
        result[rule["policy"]].append(converted)

    for policy in result:
        result[policy] = list(dict.fromkeys(result[policy]))

    return result, skipped


# ------------------------------------------------------------
# Clash
# ------------------------------------------------------------

def convert_clash(rule):
    parts = [
        rule["type"],
        rule["value"],
        rule["policy"],
    ]
    parts.extend(rule["options"])
    return ",".join(parts)


# ------------------------------------------------------------
# Quantumult X
# ------------------------------------------------------------

def convert_qx(rule):
    mapping = {
        "DOMAIN": "host",
        "DOMAIN-SUFFIX": "host-suffix",
        "DOMAIN-KEYWORD": "host-keyword",
        "IP-CIDR": "ip-cidr",
        "IP-CIDR6": "ip6-cidr",
        "GEOIP": "geoip",
    }

    rule_type = rule["type"]

    # DST-PORT is filtered out before this function is called.
    if rule_type not in mapping:
        raise ValueError(
            f"QX does not support source rule type: {rule_type}"
        )

    value = rule["value"]
    policy = rule["policy"].lower()

    # QX IP rules use the three-field form shown in its
    # official sample configuration.
    return f"{mapping[rule_type]}, {value}, {policy}"


# ------------------------------------------------------------
# Karing
# ------------------------------------------------------------

def karing_field(rule_type):
    mapping = {
        "DOMAIN": "domain",
        "DOMAIN-SUFFIX": "domain_suffix",
        "DOMAIN-KEYWORD": "domain_keyword",
        "IP-CIDR": "ip_cidr",
        "IP-CIDR6": "ip_cidr",
        "GEOIP": "geoip",
        "DST-PORT": "port",
    }

    return mapping[rule_type]


def make_karing(rules, policy, name, outbound):
    grouped = {}

    for rule in rules:
        if rule["policy"] != policy:
            continue

        field = karing_field(rule["type"])
        value = rule["value"]

        grouped.setdefault(field, [])
        unique_append(grouped[field], value)

    result_rule = {
        "outbound": outbound,
        "name": name,
        "switch": True,
        "or": False,
    }

    field_order = [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "ip_cidr",
        "geoip",
        "port",
    ]

    for field in field_order:
        if grouped.get(field):
            result_rule[field] = grouped[field]

    return {
        "version": 1,
        "rules": [result_rule],
    }


# ------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------

def write_text(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)

    content = "\n".join(lines)
    if lines:
        content += "\n"

    path.write_text(content, encoding="utf-8")


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    print("=== Unified Rule Converter ===")
    print(f"Source: {SOURCE_FILE}")
    print(f"Output: {OUTPUT_DIR}")
    print()

    rules = read_source()
    print(f"Loaded {len(rules)} unique source rules.")

    # Clash outputs
    clash, _ = split_by_policy(rules, convert_clash, "clash")

    for policy, filename in [
        ("DIRECT", "clash-direct.list"),
        ("PROXY", "clash-proxy.list"),
        ("REJECT", "clash-reject.list"),
    ]:
        write_text(
            OUTPUT_DIR / filename,
            clash[policy],
        )

    # Quantumult X outputs
    qx, skipped_qx = split_by_policy(rules, convert_qx, "qx")

    for policy, filename in [
        ("DIRECT", "qx-direct.list"),
        ("PROXY", "qx-proxy.list"),
        ("REJECT", "qx-reject.list"),
    ]:
        write_text(
            OUTPUT_DIR / filename,
            qx[policy],
        )

    # Karing outputs
    karing_files = [
        ("DIRECT", "GitHub Direct", "direct",
         "karing-direct.json"),
        ("PROXY", "GitHub Proxy", "proxy",
         "karing-proxy.json"),
        ("REJECT", "GitHub Reject", "block",
         "karing-reject.json"),
    ]

    for policy, name, outbound, filename in karing_files:
        data = make_karing(rules, policy, name, outbound)
        write_json(OUTPUT_DIR / filename, data)

    print()
    print("Clash:")
    print(f"  Direct: {len(clash['DIRECT'])}")
    print(f"  Proxy:  {len(clash['PROXY'])}")
    print(f"  Reject: {len(clash['REJECT'])}")

    print()
    print("Quantumult X:")
    print(f"  Direct: {len(qx['DIRECT'])}")
    print(f"  Proxy:  {len(qx['PROXY'])}")
    print(f"  Reject: {len(qx['REJECT'])}")

    if skipped_qx:
        print()
        print("Skipped for QX (unsupported rule type):")
        for rule in skipped_qx:
            print(
                f"  source line {rule['line']}: "
                f"{rule['type']},{rule['value']},{rule['policy']}"
            )

    print()
    print("Conversion completed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nERROR: {error}", file=sys.stderr)
        sys.exit(1)
