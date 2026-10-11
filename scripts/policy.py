"""Detection policy manager — the ONLY way rules and engines are changed.

Rules are never edited through the admin portal: the portal's Rules & Engines
tab is read-only. This script edits the policy INI (default conf/policy.ini,
or the file named by conf/pif.ini [pif] policy_file). The running firewall
watches that file and hot-reloads it, so every command below is LIVE from the
next scan — no restart needed.

Commands:
  list                                  show engines + every detection
  enable  <RULE-001|FUZZY-001|CUSTOM-x> enable a detection
  disable <RULE-001|FUZZY-001|CUSTOM-x> disable a detection
  weight  <id> <0..1>                   re-weight a detection
  severity <id> <0..1>                  re-tune a detection's severity
  engine  <name> <on|off>               rule_engine / semantic_engine /
                                        context_engine / risk_correlation
  add     <CUSTOM-id> --pattern ... --category ... [--severity 0.8]
          [--weight 1.0] [--reason ...]  add a custom rule
  remove  <CUSTOM-id>                   delete a custom rule section

Built-in detections (RULE-###/FUZZY-###) can be disabled, re-weighted or
re-tuned in severity but never removed; only [rules:CUSTOM-###] sections are
deleted by `remove`.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import configparser

from pif.detection import FUZZY_PHRASES, RULES_REGISTRY, validate_custom_rule

ENGINES = ("rule_engine", "semantic_engine", "context_engine", "risk_correlation")


def policy_path(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    parser = configparser.ConfigParser()
    parser.read(Path("conf/pif.ini"), encoding="utf-8")
    if parser.has_option("pif", "policy_file"):
        return Path(parser.get("pif", "policy_file"))
    return Path("conf/policy.ini")


def known_ids() -> set[str]:
    return {rule["id"] for rule in RULES_REGISTRY} | {fuzzy[0] for fuzzy in FUZZY_PHRASES}


def load(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    if path.is_file():
        parser.read(path, encoding="utf-8")
    return parser


def save(path: Path, parser: configparser.ConfigParser) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(
            "# Policy engine configuration: thresholds, policy actions, detection\n"
            "# engine toggles and per-rule overrides. Managed by scripts/policy.py\n"
            "# (the admin portal is read-only); the firewall hot-reloads this file.\n\n"
        )
        parser.write(handle)
    temporary.replace(path)


def set_override(parser: configparser.ConfigParser, rule_id: str, key: str, value: str) -> None:
    section = f"rules:{rule_id}"
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, key, value)


def print_list(parser: configparser.ConfigParser) -> None:
    detection = parser["detection"] if parser.has_section("detection") else {}
    print("engines:")
    for name in ENGINES:
        raw = detection.get(name, "true")
        print(f"  {name:<18} {'ON' if raw.lower() != 'false' else 'OFF'}")
    print("\ndetections:")
    print(f"  {'ID':<12} {'CATEGORY':<22} {'SEV':<5} {'WEIGHT':<7} ENABLED SOURCE")
    rows = []
    for rule in RULES_REGISTRY:
        section = parser[f"rules:{rule['id']}"] if parser.has_section(f"rules:{rule['id']}") else {}
        rows.append((rule["id"], rule["category"], section.get("severity", rule["severity"]), section, "built-in"))
    for rule_id, category, severity, phrase in FUZZY_PHRASES:
        section = parser[f"rules:{rule_id}"] if parser.has_section(f"rules:{rule_id}") else {}
        rows.append((rule_id, category, section.get("severity", severity), section, "fuzzy"))
    for section_name in parser.sections():
        if not section_name.startswith("rules:"):
            continue
        rule_id = section_name.split(":", 1)[1]
        if rule_id in known_ids() or not parser.get(section_name, "pattern", fallback=""):
            continue
        section = parser[section_name]
        rows.append(
            (
                rule_id,
                section.get("category", "?"),
                section.get("severity", "?"),
                section,
                "custom",
            )
        )
    for rule_id, category, severity, section, source in rows:
        enabled = section.get("enabled", "true").lower() != "false"
        weight = section.get("weight", "1.0")
        print(
            f"  {rule_id:<12} {str(category):<22} {str(severity):<5} {weight:<7} "
            f"{'yes' if enabled else 'NO':<7} {source}"
        )


def known_or_custom(parser: configparser.ConfigParser, rule_id: str) -> bool:
    """A detection the script may tune: built-in (RULE-###/FUZZY-###) or a
    CUSTOM- section that already carries a full definition."""
    if rule_id in known_ids():
        return True
    section = f"rules:{rule_id}"
    return parser.has_section(section) and bool(
        parser.get(section, "pattern", fallback="")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("Commands:")[0])
    parser.add_argument("--file", help="policy INI path (default: conf/pif.ini [pif] policy_file)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    for name in ("enable", "disable"):
        cmd = sub.add_parser(name)
        cmd.add_argument("rule_id")
    weight = sub.add_parser("weight")
    weight.add_argument("rule_id")
    weight.add_argument("value", type=float)
    severity = sub.add_parser("severity")
    severity.add_argument("rule_id")
    severity.add_argument("value", type=float)
    engine = sub.add_parser("engine")
    engine.add_argument("name", choices=ENGINES)
    engine.add_argument("state", choices=["on", "off"])
    add = sub.add_parser("add")
    add.add_argument("rule_id")
    add.add_argument("--pattern", required=True)
    add.add_argument("--category", required=True)
    add.add_argument("--severity", type=float, default=0.8)
    add.add_argument("--weight", type=float, default=1.0)
    add.add_argument("--reason", default="custom detection added by scripts/policy.py")
    remove = sub.add_parser("remove")
    remove.add_argument("rule_id")
    args = parser.parse_args()

    path = policy_path(args.file)
    ini = load(path)
    custom_section = f"rules:{args.rule_id}" if getattr(args, "rule_id", "") else None

    if args.command == "list":
        print_list(ini)
        return 0
    if args.command in ("enable", "disable"):
        if not known_or_custom(ini, args.rule_id):
            print(f"unknown detection: {args.rule_id}")
            return 1
        set_override(ini, args.rule_id, "enabled", "true" if args.command == "enable" else "false")
    if args.command in ("weight", "severity"):
        if not known_or_custom(ini, args.rule_id):
            print(f"unknown detection: {args.rule_id}")
            return 1
        # weight is a multiplier in [0,1]; severity is a score in (0,1] —
        # the same bounds validate_custom_rule enforces for CUSTOM rules.
        valid = 0 <= args.value <= 1 if args.command == "weight" else 0 < args.value <= 1
        if not valid:
            print(f"{args.command} must be within {'[0,1]' if args.command == 'weight' else '(0,1]'}")
            return 1
        set_override(ini, args.rule_id, args.command, str(round(args.value, 4)))
    if args.command == "engine":
        if not ini.has_section("detection"):
            ini.add_section("detection")
        ini.set("detection", args.name, "true" if args.state == "on" else "false")
    if args.command == "add":
        try:
            rule = validate_custom_rule(
                args.rule_id,
                {
                    "pattern": args.pattern,
                    "category": args.category,
                    "severity": args.severity,
                    "weight": args.weight,
                    "reason": args.reason,
                },
            )
        except ValueError as error:
            print(f"invalid custom rule: {error}")
            return 1
        section = f"rules:{rule['id']}"
        if ini.has_section(section):
            ini.remove_section(section)
        ini.add_section(section)
        ini.set(section, "weight", str(rule.get("weight", 1.0)))
        ini.set(section, "category", rule["category"])
        ini.set(section, "severity", str(rule["severity"]))
        ini.set(section, "pattern", rule["pattern"])
        ini.set(section, "reason", rule["reason"])
    if args.command == "remove":
        if args.rule_id in known_ids():
            print("built-in detections cannot be removed — disable them instead")
            return 1
        if not ini.has_section(custom_section):
            print(f"no such custom rule: {args.rule_id}")
            return 1
        ini.remove_section(custom_section)

    save(path, ini)
    print(f"policy updated: {path} (the firewall hot-reloads it — live from the next scan)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
