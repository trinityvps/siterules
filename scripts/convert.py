from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parent.parent

SOURCE = ROOT / "source" / "rules.list"
OUTPUT = ROOT / "generated"

OUTPUT.mkdir(parents=True, exist_ok=True)


# ============================================================
# 基础工具
# ============================================================

def normalize_policy(policy):
    policy = policy.strip().upper()

    aliases = {
        "DIRECT": "DIRECT",
        "PROXY": "PROXY",
        "REJECT": "REJECT",
        "BLOCK": "REJECT",
    }

    return aliases.get(policy, policy)


def qx_policy(policy):
    mapping = {
        "DIRECT": "direct",
        "PROXY": "proxy",
        "REJECT": "reject",
    }

    return mapping.get(policy, policy)


def parse_rule(line):
    line = line.strip()

    if not line:
        return None

    if line.startswith("#"):
        return None

    parts = [x.strip() for x in line.split(",")]

    if len(parts) < 2:
        return None

    rule_type = parts[0].upper()
    value = parts[1]

    policy = ""

    if len(parts) >= 3:
        policy = normalize_policy(parts[2])

    options = parts[3:]

    return {
        "type": rule_type,
        "value": value,
        "policy": policy,
        "options": options,
        "original": line,
    }


# ============================================================
# QX 转换
# ============================================================

def convert_qx(rule):

    rule_type = rule["type"]
    value = rule["value"]
    policy = qx_policy(rule["policy"])

    if rule_type == "DOMAIN-SUFFIX":
        return f"host-suffix, {value}, {policy}"

    if rule_type == "DOMAIN":
        return f"host, {value}, {policy}"

    if rule_type == "DOMAIN-KEYWORD":
        return f"host-keyword, {value}, {policy}"

    if rule_type == "IP-CIDR":
        return f"ip-cidr, {value}, {policy}, no-resolve"

    if rule_type == "IP-CIDR6":
        return f"ip6-cidr, {value}, {policy}, no-resolve"

    if rule_type == "GEOIP":
        return f"geoip, {value}, {policy}"

    return None


# ============================================================
# Karing 转换
# ============================================================

def convert_karing(rule):

    rule_type = rule["type"]
    value = rule["value"]

    if rule_type == "DOMAIN-SUFFIX":
        return "domain_suffix", value

    if rule_type == "DOMAIN":
        return "domain", value

    if rule_type == "DOMAIN-KEYWORD":
        return "domain_keyword", value

    if rule_type == "IP-CIDR":
        return "ip_cidr", value

    if rule_type == "IP-CIDR6":
        return "ip_cidr", value

    return None


# ============================================================
# Karing JSON
# ============================================================

def create_karing_rule(name, outbound, rules):

    result = {
        "outbound": outbound,
        "name": name,
        "switch": True,
        "or": False
    }

    # Karing 的规则类型
    # domain_suffix
    # domain
    # domain_keyword
    # ip_cidr

    for key in [
        "domain_suffix",
        "domain",
        "domain_keyword",
        "ip_cidr"
    ]:

        if key in rules and rules[key]:
            result[key] = sorted(set(rules[key]))

    return result


# ============================================================
# 读取
# ============================================================

if not SOURCE.exists():
    print(f"ERROR: {SOURCE} does not exist.")
    sys.exit(1)


lines = SOURCE.read_text(
    encoding="utf-8"
).splitlines()


# ============================================================
# 输出容器
# ============================================================

clash_direct = []
clash_proxy = []
clash_reject = []

qx_direct = []
qx_proxy = []
qx_reject = []

karing_direct = {
    "domain_suffix": [],
    "domain": [],
    "domain_keyword": [],
    "ip_cidr": []
}

karing_proxy = {
    "domain_suffix": [],
    "domain": [],
    "domain_keyword": [],
    "ip_cidr": []
}

karing_reject = {
    "domain_suffix": [],
    "domain": [],
    "domain_keyword": [],
    "ip_cidr": []
}


errors = []


# ============================================================
# 转换
# ============================================================

for line_number, line in enumerate(lines, start=1):

    stripped = line.strip()

    # 空行
    if not stripped:
        continue

    # 注释
    if stripped.startswith("#"):

        clash_direct.append(stripped)
        clash_proxy.append(stripped)

        qx_direct.append(stripped)
        qx_proxy.append(stripped)

        continue

    rule = parse_rule(line)

    if not rule:
        continue

    rule_type = rule["type"]
    policy = rule["policy"]

    # --------------------------------------------------------
    # 不支持的规则类型
    # --------------------------------------------------------

    supported = {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP"
    }

    if rule_type not in supported:

        errors.append(
            f"Line {line_number}: "
            f"unsupported rule type: {rule_type}"
        )

        continue

    # --------------------------------------------------------
    # Clash
    # --------------------------------------------------------

    if policy == "DIRECT":
        clash_direct.append(stripped)

    elif policy == "PROXY":
        clash_proxy.append(stripped)

    elif policy == "REJECT":
        clash_reject.append(stripped)

    # --------------------------------------------------------
    # Quantumult X
    # --------------------------------------------------------

    qx = convert_qx(rule)

    if qx:

        if policy == "DIRECT":
            qx_direct.append(qx)

        elif policy == "PROXY":
            qx_proxy.append(qx)

        elif policy == "REJECT":
            qx_reject.append(qx)

    # --------------------------------------------------------
    # Karing
    # --------------------------------------------------------

    karing = convert_karing(rule)

    if karing:

        key, value = karing

        if policy == "DIRECT":
            karing_direct[key].append(value)

        elif policy == "PROXY":
            karing_proxy[key].append(value)

        elif policy == "REJECT":
            karing_reject[key].append(value)


# ============================================================
# 去重
# ============================================================

def unique_lines(lines):

    result = []
    seen = set()

    for line in lines:

        key = line.strip()

        if not key:
            continue

        if key in seen:
            continue

        seen.add(key)
        result.append(line)

    return result


clash_direct = unique_lines(clash_direct)
clash_proxy = unique_lines(clash_proxy)
clash_reject = unique_lines(clash_reject)

qx_direct = unique_lines(qx_direct)
qx_proxy = unique_lines(qx_proxy)
qx_reject = unique_lines(qx_reject)


# ============================================================
# 写 Clash
# ============================================================

def write_text(filename, lines):

    path = OUTPUT / filename

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )


write_text(
    "clash-direct.list",
    clash_direct
)

write_text(
    "clash-proxy.list",
    clash_proxy
)

write_text(
    "clash-reject.list",
    clash_reject
)


# ============================================================
# 写 Quantumult X
# ============================================================

write_text(
    "qx-direct.list",
    qx_direct
)

write_text(
    "qx-proxy.list",
    qx_proxy
)

write_text(
    "qx-reject.list",
    qx_reject
)


# ============================================================
# Karing
# ============================================================

def clean_karing(rules):

    result = {}

    for key, values in rules.items():

        values = sorted(set(values))

        if values:
            result[key] = values

    return result


karing_direct = clean_karing(karing_direct)
karing_proxy = clean_karing(karing_proxy)
karing_reject = clean_karing(karing_reject)


def write_karing(filename, name, outbound, rules):

    rule = create_karing_rule(
        name=name,
        outbound=outbound,
        rules=rules
    )

    output = {
        "version": 1,
        "rules": [
            rule
        ]
    }

    path = OUTPUT / filename

    path.write_text(
        json.dumps(
            output,
            ensure_ascii=False,
            separators=(",", ":")
        ),
        encoding="utf-8"
    )


write_karing(
    "karing-direct.json",
    "GitHub Direct",
    "direct",
    karing_direct
)

write_karing(
    "karing-proxy.json",
    "GitHub Proxy",
    "proxy",
    karing_proxy
)

write_karing(
    "karing-reject.json",
    "GitHub Reject",
    "block",
    karing_reject
)


# ============================================================
# 输出结果
# ============================================================

print("======================================")
print("Rule conversion completed")
print("======================================")

print(f"Clash Direct : {len(clash_direct)} lines")
print(f"Clash Proxy  : {len(clash_proxy)} lines")
print(f"Clash Reject : {len(clash_reject)} lines")

print(f"QX Direct    : {len(qx_direct)} lines")
print(f"QX Proxy     : {len(qx_proxy)} lines")
print(f"QX Reject    : {len(qx_reject)} lines")

print(
    "Karing Direct:",
    sum(len(v) for v in karing_direct.values())
)

print(
    "Karing Proxy :",
    sum(len(v) for v in karing_proxy.values())
)

print(
    "Karing Reject:",
    sum(len(v) for v in karing_reject.values())
)


# ============================================================
# 错误检查
# ============================================================

if errors:

    print("")
    print("WARNING:")
    print("The following rules were not converted:")

    for error in errors:
        print(error)

    # 不让 GitHub Actions 因为未知规则直接失败
    # 方便以后逐步增加规则类型

print("")
print("Done.")
