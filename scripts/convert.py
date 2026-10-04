#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified Rule Converter

Source:
    source/rules.list

Generated:
    generated/
        clash-direct.list
        clash-proxy.list
        clash-reject.list

        qx-direct.list
        qx-proxy.list
        qx-reject.list

        karing-direct.json
        karing-proxy.json
        karing-reject.json

Supported source rule types:
    DOMAIN
    DOMAIN-SUFFIX
    DOMAIN-KEYWORD
    IP-CIDR
    IP-CIDR6
    GEOIP
    DST-PORT

Supported policies:
    DIRECT
    PROXY
    REJECT
    BLOCK -> REJECT
"""

from pathlib import Path
import json
import sys


# ============================================================
# Paths
# ============================================================

ROOT = Path(__file__).resolve().parent.parent

SOURCE_FILE = ROOT / "source" / "rules.list"
OUTPUT_DIR = ROOT / "generated"


# ============================================================
# Supported rule types
# ============================================================

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


# ============================================================
# Utility
# ============================================================

def normalize_policy(policy: str) -> str:
    """
    Normalize policy names.

    BLOCK -> REJECT
    """

    policy = policy.strip().upper()

    if policy == "BLOCK":
        return "REJECT"

    return policy


def normalize_rule_type(rule_type: str) -> str:
    return rule_type.strip().upper()


def split_rule(line: str):
    """
    Parse:

        TYPE,value,POLICY

    or:

        TYPE,value,POLICY,OPTION

    Example:

        IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
        DST-PORT,53317,DIRECT
    """

    parts = [x.strip() for x in line.split(",")]

    if len(parts) < 3:
        raise ValueError(
            f"Invalid rule: {line}"
        )

    rule_type = normalize_rule_type(parts[0])
    value = parts[1]
    policy = normalize_policy(parts[2])
    options = parts[3:]

    return rule_type, value, policy, options


def unique_append(target, value):
    """
    Append only if not already present.
    """

    if value not in target:
        target.append(value)


# ============================================================
# Read source rules
# ============================================================

def read_source():
    if not SOURCE_FILE.exists():
        raise FileNotFoundError(
            f"Source file not found: {SOURCE_FILE}"
        )

    rules = []

    with SOURCE_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:

        for line_number, raw_line in enumerate(f, start=1):

            line = raw_line.strip()

            # Empty line
            if not line:
                continue

            # Comment
            if line.startswith("#"):
                continue

            try:
                rule_type, value, policy, options = split_rule(line)

            except Exception as e:
                raise ValueError(
                    f"Line {line_number}: {e}"
                )

            if rule_type not in SUPPORTED_TYPES:
                raise ValueError(
                    f"Line {line_number}: "
                    f"Unsupported rule type: {rule_type}\n"
                    f"    {line}"
                )

            if policy not in SUPPORTED_POLICIES:
                raise ValueError(
                    f"Line {line_number}: "
                    f"Unsupported policy: {policy}\n"
                    f"    {line}"
                )

            # BLOCK has already been normalized to REJECT.
            policy = normalize_policy(policy)

            rules.append({
                "type": rule_type,
                "value": value,
                "policy": policy,
                "options": options,
                "line": line_number,
            })

    return rules


# ============================================================
# Clash
# ============================================================

def convert_clash_rule(rule):
    """
    Clash classical rule format.

    Source rule is already mostly compatible with Clash.

    We intentionally preserve DST-PORT because Clash
    classical rules support it.
    """

    rule_type = rule["type"]
    value = rule["value"]
    policy = rule["policy"]
    options = rule["options"]

    parts = [
        rule_type,
        value,
        policy,
    ]

    # Preserve options such as no-resolve.
    #
    # Example:
    # IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
    #
    # If no option was supplied, don't add one.
    if options:
        parts.extend(options)

    return ",".join(parts)


def generate_clash(rules):

    direct = []
    proxy = []
    reject = []

    for rule in rules:

        line = convert_clash_rule(rule)

        policy = rule["policy"]

        if policy == "DIRECT":
            unique_append(direct, line)

        elif policy == "PROXY":
            unique_append(proxy, line)

        elif policy == "REJECT":
            unique_append(reject, line)

    return direct, proxy, reject


# ============================================================
# Quantumult X
# ============================================================

def convert_qx_rule(rule):
    """
    Convert unified source syntax to Quantumult X.

    DOMAIN
        -> host

    DOMAIN-SUFFIX
        -> host-suffix

    DOMAIN-KEYWORD
        -> host-keyword

    IP-CIDR
        -> ip-cidr

    IP-CIDR6
        -> ip6-cidr

    GEOIP
        -> geoip

    DST-PORT
        -> dst-port
    """

    rule_type = rule["type"]
    value = rule["value"]
    policy = rule["policy"]

    # QX policy names are lowercase.
    qx_policy = policy.lower()

    mapping = {
        "DOMAIN": "host",
        "DOMAIN-SUFFIX": "host-suffix",
        "DOMAIN-KEYWORD": "host-keyword",
        "IP-CIDR": "ip-cidr",
        "IP-CIDR6": "ip6-cidr",
        "GEOIP": "geoip",
        "DST-PORT": "dst-port",
    }

    qx_type = mapping[rule_type]

    # IP rules should use no-resolve.
    if rule_type in {
        "IP-CIDR",
        "IP-CIDR6",
    }:

        return (
            f"{qx_type},"
            f"{value},"
            f"{qx_policy},"
            f"no-resolve"
        )

    return (
        f"{qx_type},"
        f"{value},"
        f"{qx_policy}"
    )


def generate_qx(rules):

    direct = []
    proxy = []
    reject = []

    for rule in rules:

        line = convert_qx_rule(rule)

        policy = rule["policy"]

        if policy == "DIRECT":
            unique_append(direct, line)

        elif policy == "PROXY":
            unique_append(proxy, line)

        elif policy == "REJECT":
            unique_append(reject, line)

    return direct, proxy, reject


# ============================================================
# Karing
# ============================================================

def karing_rule_field(rule_type):
    """
    Convert source rule type to Karing JSON field.
    """

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


def convert_karing_rules(rules, policy):

    grouped = {}

    for rule in rules:

        if rule["policy"] != policy:
            continue

        rule_type = rule["type"]
        value = rule["value"]

        field = karing_rule_field(rule_type)

        if field not in grouped:
            grouped[field] = []

        if value not in grouped[field]:
            grouped[field].append(value)

    return grouped


def generate_karing(rules, policy, name, outbound):

    grouped = convert_karing_rules(
        rules,
        policy
    )

    rule = {
        "outbound": outbound,
        "name": name,
        "switch": True,
        "or": False,
    }

    # Keep a stable field order.
    field_order = [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "ip_cidr",
        "geoip",
        "port",
    ]

    for field in field_order:

        if field in grouped and grouped[field]:
            rule[field] = grouped[field]

    return {
        "version": 1,
        "rules": [
            rule
        ]
    }


# ============================================================
# Write files
# ============================================================

def write_text(path, lines):

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    content = "\n".join(lines)

    if lines:
        content += "\n"

    path.write_text(
        content,
        encoding="utf-8"
    )


def write_json(path, data):

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ) + "\n",
        encoding="utf-8"
    )


# ============================================================
# Main
# ============================================================

def main():

    print("========================================")
    print(" Unified Rule Converter")
    print("========================================")
    print()

    print(f"Source: {SOURCE_FILE}")
    print(f"Output: {OUTPUT_DIR}")
    print()

    # --------------------------------------------------------
    # Read
    # --------------------------------------------------------

    rules = read_source()

    print(f"Loaded {len(rules)} rules.")
    print()

    # --------------------------------------------------------
    # Generate Clash
    # --------------------------------------------------------

    clash_direct, clash_proxy, clash_reject = \
        generate_clash(rules)

    write_text(
        OUTPUT_DIR / "clash-direct.list",
        clash_direct
    )

    write_text(
        OUTPUT_DIR / "clash-proxy.list",
        clash_proxy
    )

    write_text(
        OUTPUT_DIR / "clash-reject.list",
        clash_reject
    )

    # --------------------------------------------------------
    # Generate Quantumult X
    # --------------------------------------------------------

    qx_direct, qx_proxy, qx_reject = \
        generate_qx(rules)

    write_text(
        OUTPUT_DIR / "qx-direct.list",
        qx_direct
    )

    write_text(
        OUTPUT_DIR / "qx-proxy.list",
        qx_proxy
    )

    write_text(
        OUTPUT_DIR / "qx-reject.list",
        qx_reject
    )

    # --------------------------------------------------------
    # Generate Karing
    # --------------------------------------------------------

    karing_direct = generate_karing(
        rules,
        "DIRECT",
        "GitHub Direct",
        "direct"
    )

    karing_proxy = generate_karing(
        rules,
        "PROXY",
        "GitHub Proxy",
        "proxy"
    )

    karing_reject = generate_karing(
        rules,
        "REJECT",
        "GitHub Reject",
        "block"
    )

    write_json(
        OUTPUT_DIR / "karing-direct.json",
        karing_direct
    )

    write_json(
        OUTPUT_DIR / "karing-proxy.json",
        karing_proxy
    )

    write_json(
        OUTPUT_DIR / "karing-reject.json",
        karing_reject
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("Generated:")
    print()

    print(
        f"  Clash Direct : {len(clash_direct)}"
    )

    print(
        f"  Clash Proxy  : {len(clash_proxy)}"
    )

    print(
        f"  Clash Reject : {len(clash_reject)}"
    )

    print()

    print(
        f"  QX Direct    : {len(qx_direct)}"
    )

    print(
        f"  QX Proxy     : {len(qx_proxy)}"
    )

    print(
        f"  QX Reject    : {len(qx_reject)}"
    )

    print()

    print("Karing:")
    print(
        f"  Direct       : "
        f"{len(karing_direct['rules'][0]) - 4} fields"
    )

    print(
        f"  Proxy        : "
        f"{len(karing_proxy['rules'][0]) - 4} fields"
    )

    print(
        f"  Reject       : "
        f"{len(karing_reject['rules'][0]) - 4} fields"
    )

    print()
    print("Conversion completed successfully.")


if __name__ == "__main__":

    try:
        main()

    except Exception as e:

        print()
        print("ERROR:")
        print(str(e))
        print()

        sys.exit(1)
