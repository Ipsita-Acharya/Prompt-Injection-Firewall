"""Report generation (JSON + CSV) controlled by conf/reporting.ini.

Every report script hands its payload to write_report(); enablement, output
location and report-specific options come exclusively from the INI file so
reporting can be reconfigured without touching code."""

import configparser
import csv
import json
from pathlib import Path

DEFAULT_CONF = Path("conf/reporting.ini")
_DELIMITERS = {"comma": ",", "semicolon": ";", "tab": "\t"}


def load_config(path: Path = DEFAULT_CONF) -> dict:
    config = {
        "output_dir": "reports",
        "json_enabled": True,
        "csv_enabled": True,
        "json_indent": 2,
        "csv_delimiter": "comma",
    }
    if path.is_file():
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        if parser.has_section("reporting"):
            section = parser["reporting"]
            config["output_dir"] = section.get("output_dir", config["output_dir"])
            config["json_enabled"] = section.getboolean("json_enabled", config["json_enabled"])
            config["csv_enabled"] = section.getboolean("csv_enabled", config["csv_enabled"])
            config["json_indent"] = section.getint("json_indent", config["json_indent"])
            config["csv_delimiter"] = section.get("csv_delimiter", config["csv_delimiter"])
    config["csv_delimiter"] = _DELIMITERS.get(config["csv_delimiter"], ",")
    return config


def _section_flag(path: Path, section: str, key: str, default: bool) -> bool:
    if not path.is_file():
        return default
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    if parser.has_section(section) and parser.has_option(section, key):
        return parser[section].getboolean(key)
    return default


def write_report(
    name: str,
    payload: dict,
    csv_rows: list[dict] | None = None,
    csv_name: str | None = None,
    conf_path: Path = DEFAULT_CONF,
) -> dict[str, Path]:
    """Write `payload` as JSON and `csv_rows` as CSV according to the INI
    configuration. Returns the dict of written paths keyed by format."""
    config = load_config(conf_path)
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    if config["json_enabled"]:
        path = output_dir / f"{name}.json"
        path.write_text(
            json.dumps(payload, indent=config["json_indent"]), encoding="utf-8"
        )
        written["json"] = path
    if config["csv_enabled"] and csv_rows:
        path = output_dir / f"{csv_name or name}.csv"
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=list(csv_rows[0].keys()), delimiter=config["csv_delimiter"]
            )
            writer.writeheader()
            writer.writerows(csv_rows)
        written["csv"] = path
    return written


def evaluation_report_options(conf_path: Path = DEFAULT_CONF) -> dict:
    return {
        "include_outcomes": _section_flag(
            conf_path, "evaluation_report", "include_outcomes", True
        )
    }


def rule_analytics_report_options(conf_path: Path = DEFAULT_CONF) -> dict:
    return {
        "include_suggestions": _section_flag(
            conf_path, "rule_analytics_report", "include_suggestions", True
        )
    }
