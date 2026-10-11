import configparser
import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    api_token: str = ""
    rules_only: bool = False
    model_path: Path = Path("models/classifier.json")
    max_bytes: int = 10 * 1024 * 1024
    max_chars: int = 250_000
    parser_timeout: float = 20.0
    ocr_enabled: bool = False
    session_ttl: float = 900.0
    max_sessions: int = 1000
    log_dir: Path = Path("logs")
    log_level: str = "DEBUG"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5
    # Mirror log lines on stderr (readable narrative when log_simple, else JSON).
    log_console: bool = True
    # Privacy gate (spec §13): False writes "[content logging disabled]" instead
    # of raw prompt/file/evidence text. Opt in only for controlled local data.
    log_content: bool = False
    # Per-preview character cap: a 10 MiB document must not flood the logs.
    # 0 disables the cap and logs the full content of every stage.
    log_content_max_chars: int = 4096
    # Attach the human-readable narrative stream (PIL_SMOD.log + console lines).
    log_simple: bool = True
    log_script_details: bool = True
    log_scan_id: bool = True
    # Policy engine (spec: configurable thresholds, actions, quarantine).
    block_threshold: float = 0.85
    hard_block_threshold: float = 0.95
    sanitize_threshold: float = 0.5
    quarantine_enabled: bool = True
    quarantine_dir: Path = Path("quarantine")
    # File-format processing limits (v6.3): previously hardcoded in the
    # parsers, now first-class settings so the portal Settings page can show
    # and change them. Defaults preserve the shipped behavior exactly.
    pdf_max_pages: int = 100
    zip_entry_limit: int = 100
    docx_max_uncompressed_bytes: int = 50 * 1024 * 1024
    zip_expansion_limit: int = 100
    image_pixel_limit: int = 20_000_000
    attachment_max_depth: int = 2
    max_extracted_segments: int = 2000
    # Concurrency limits (v6.3): scans running simultaneously in the process,
    # and file-parsing worker subprocesses running at once. Defaults preserve
    # the previously hardcoded values (4 scans / 2 parsers); raise them via
    # conf or environment for high-throughput deployments.
    scan_concurrency: int = 4
    parser_concurrency: int = 2
    # Per-scan SQLite report (request, decision, findings) consumed by the admin portal.
    report_db_enabled: bool = True
    report_db_path: Path = Path("data/report.db")
    # Policy INI (rules, engine toggles, thresholds) — the single source of
    # truth, managed by scripts; the firewall hot-reloads it when it changes.
    policy_file: Path = Path("conf/policy.ini")
    policy_config: dict = field(default_factory=dict)

    def log_configuration(self):
        from pif.observability import logger

        logger.info("settings.loaded", extra={"event_fields": dict(token_configured=bool(self.api_token), rules_only=self.rules_only, ocr_enabled=self.ocr_enabled, max_file_bytes=self.max_bytes, max_text_chars=self.max_chars, parser_timeout_seconds=self.parser_timeout, session_ttl_seconds=self.session_ttl, max_sessions=self.max_sessions, diagnostic_content_enabled=self.log_content, diagnostic_preview_limit=self.log_content_max_chars, simple_log_enabled=self.log_simple)})

    def __post_init__(self):
        if (
            min(
                self.max_bytes,
                self.max_chars,
                self.parser_timeout,
                self.session_ttl,
                self.max_sessions,
            )
            <= 0
        ):
            raise ValueError("Security limits must be positive")
        if self.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("Invalid PIF_LOG_LEVEL")
        if self.log_max_bytes <= 0 or self.log_backup_count <= 0:
            raise ValueError("Log rotation limits must be positive")
        if not 0 <= self.log_content_max_chars <= 65536:
            raise ValueError("PIF_LOG_CONTENT_MAX_CHARS must be between 0 and 65536 (0 = unlimited)")
        for name in ("block_threshold", "hard_block_threshold", "sanitize_threshold"):
            value = getattr(self, name)
            if not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.block_threshold > self.hard_block_threshold:
            raise ValueError("block_threshold must not exceed hard_block_threshold")
        for name in (
            "pdf_max_pages",
            "zip_entry_limit",
            "zip_expansion_limit",
            "image_pixel_limit",
            "attachment_max_depth",
            "max_extracted_segments",
            "scan_concurrency",
            "parser_concurrency",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.docx_max_uncompressed_bytes <= 0:
            raise ValueError("docx_max_uncompressed_bytes must be positive")

    @staticmethod
    def _load_policy_file(path: Path) -> dict:
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            return document if isinstance(document, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _resolve_policy_override_file() -> Path | None:
        """The agent's approved overrides land in a PIF_POLICY_FILE JSON; that
        file must reach the INI-configured server too, or an approved fix
        would never influence production behavior. Default to the agent's
        override file when it exists so an approval is effective from the
        next server start without extra configuration."""
        env_policy = os.getenv("PIF_POLICY_FILE", "")
        if not env_policy:
            default_override = Path("conf/policy-overrides.json")
            if default_override.is_file():
                return default_override
            return None
        return Path(env_policy)

    @classmethod
    def _merged_policy_config(cls, policy_file: Path) -> dict:
        """Policy INI content with the agent override JSON merged on top.
        Re-read on every call — the firewall live-reload uses this so script
        edits to conf/policy.ini take effect without a restart."""
        config: dict = {}
        if policy_file.is_file():
            parser = configparser.ConfigParser()
            parser.read(policy_file, encoding="utf-8")
            config = cls._policy_from_ini(parser)
        override_path = cls._resolve_policy_override_file()
        if override_path is not None:
            override = cls._load_policy_file(override_path)
            for key, value in override.items():
                if isinstance(value, dict) and isinstance(config.get(key), dict):
                    config[key] = {**config[key], **value}
                else:
                    config[key] = value
        return config

    def fresh_policy_config(self) -> dict:
        return self._merged_policy_config(self.policy_file)

    @staticmethod
    def _load_token() -> str:
        token = os.getenv("PIF_API_TOKEN", "")
        token_file = Path(".pif-token")
        if not token and token_file.is_file():
            token = token_file.read_text(encoding="utf-8").strip()
        return token

    @staticmethod
    def _policy_from_ini(parser: configparser.ConfigParser) -> dict:
        config: dict = {}

        def booleans(section, keys):
            return {
                key: parser.getboolean(section, key, fallback=True)
                for key in keys
                if parser.has_option(section, key)
            }

        if parser.has_section("thresholds"):
            config["thresholds"] = {
                key: parser.getfloat("thresholds", key)
                for key in ("sanitize", "block", "hard_block")
                if parser.has_option("thresholds", key)
            }
        actions = booleans("actions", ("allow", "sanitize", "block", "partial_block", "quarantine"))
        if actions:
            config["actions"] = actions
        detection = booleans(
            "detection",
            ("rule_engine", "semantic_engine", "context_engine", "risk_correlation"),
        )
        if detection:
            config["detection"] = detection
        rules = {}
        for section in parser.sections():
            if not section.startswith("rules:"):
                continue
            entry = {
                key: parser.getboolean(section, key)
                if key == "enabled"
                else parser.getfloat(section, key)
                if key in ("weight", "severity")
                else parser.get(section, key)
                for key in ("enabled", "weight", "severity", "pattern", "category", "reason")
                if parser.has_option(section, key)
            }
            rules[section.split(":", 1)[1]] = entry
        if rules:
            config["rules"] = rules
        return config

    @staticmethod
    def _as_bool(value: str) -> bool:
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def from_ini(cls, path: Path | None = None):
        """Build Settings from an INI configuration file (conf/pif.ini).
        The API token still comes from PIF_API_TOKEN or the .pif-token file."""
        path = Path(path) if path else Path("conf/pif.ini")
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")

        def get(section, key, default, cast=str):
            if parser.has_section(section) and parser.has_option(section, key):
                return cast(parser[section][key])
            return default

        def get_bool(section, key, default):
            if parser.has_section(section) and parser.has_option(section, key):
                return cls._as_bool(parser[section][key])
            return default

        thresholds_ini = Path(
            get("pif", "policy_file", "conf/policy.ini")
        )
        policy_config = cls._merged_policy_config(thresholds_ini)
        thresholds = policy_config.get("thresholds", {})
        log_section = "logging"
        return cls(
            api_token=cls._load_token(),
            rules_only=get_bool("pif", "rules_only", False),
            model_path=Path(get("pif", "model_path", "models/classifier.json")),
            max_bytes=get("pif", "max_bytes", 10 * 1024 * 1024, int),
            max_chars=get("pif", "max_chars", 250_000, int),
            parser_timeout=get("pif", "parser_timeout", 20.0, float),
            ocr_enabled=get_bool("pif", "ocr_enabled", False),
            session_ttl=get("pif", "session_ttl", 900.0, float),
            max_sessions=get("pif", "max_sessions", 1000, int),
            log_dir=Path(get(log_section, "dir", "logs")),
            log_level=get(log_section, "level", "DEBUG").upper(),
            log_max_bytes=get(log_section, "max_bytes", 10 * 1024 * 1024, int),
            log_backup_count=get(log_section, "backup_count", 5, int),
            log_console=get_bool(log_section, "console", True),
            log_content=get_bool(log_section, "content", False),
            log_content_max_chars=get(log_section, "content_max_chars", 4096, int),
            log_simple=get_bool(log_section, "simple", True),
            log_script_details=get_bool(log_section, "script_details", True),
            log_scan_id=get_bool(log_section, "scan_id", True),
            block_threshold=get("pif", "block_threshold", thresholds.get("block", 0.85), float),
            hard_block_threshold=get(
                "pif", "hard_block_threshold", thresholds.get("hard_block", 0.95), float
            ),
            sanitize_threshold=get(
                "pif", "sanitize_threshold", thresholds.get("sanitize", 0.5), float
            ),
            quarantine_enabled=get_bool("pif", "quarantine_enabled", True),
            quarantine_dir=Path(get("pif", "quarantine_dir", "quarantine")),
            report_db_enabled=get_bool("pif", "report_db_enabled", True),
            report_db_path=Path(get("pif", "report_db_path", "data/report.db")),
            pdf_max_pages=get("pif", "pdf_max_pages", 100, int),
            zip_entry_limit=get("pif", "zip_entry_limit", 100, int),
            docx_max_uncompressed_bytes=get(
                "pif", "docx_max_uncompressed_bytes", 50 * 1024 * 1024, int
            ),
            zip_expansion_limit=get("pif", "zip_expansion_limit", 100, int),
            image_pixel_limit=get("pif", "image_pixel_limit", 20_000_000, int),
            attachment_max_depth=get("pif", "attachment_max_depth", 2, int),
            max_extracted_segments=get("pif", "max_extracted_segments", 2000, int),
            scan_concurrency=get("pif", "scan_concurrency", 4, int),
            parser_concurrency=get("pif", "parser_concurrency", 2, int),
            policy_file=thresholds_ini,
            policy_config=policy_config,
        )

    @classmethod
    def load(cls):
        """conf/pif.ini when present, environment variables otherwise."""
        ini = Path(os.getenv("PIF_CONF", "conf/pif.ini"))
        return cls.from_ini(ini) if ini.is_file() else cls.from_env()

    @classmethod
    def from_env(cls):
        token = cls._load_token()
        policy_path = os.getenv("PIF_POLICY_FILE", "")
        if not policy_path:
            default_override = Path("conf/policy-overrides.json")
            if default_override.is_file():
                policy_path = str(default_override)
        policy_config = cls._load_policy_file(Path(policy_path)) if policy_path else {}
        thresholds = policy_config.get("thresholds", {}) if isinstance(policy_config, dict) else {}
        try:
            block_threshold = float(
                os.getenv("PIF_BLOCK_THRESHOLD", str(thresholds.get("block", 0.85)))
            )
            hard_block_threshold = float(
                os.getenv("PIF_HARD_BLOCK_THRESHOLD", str(thresholds.get("hard_block", 0.95)))
            )
            sanitize_threshold = float(
                os.getenv("PIF_SANITIZE_THRESHOLD", str(thresholds.get("sanitize", 0.5)))
            )
        except ValueError:
            block_threshold, hard_block_threshold, sanitize_threshold = 0.85, 0.95, 0.5
        return cls(
            api_token=token,
            rules_only=os.getenv("PIF_RULES_ONLY", "0") == "1",
            model_path=Path(os.getenv("PIF_MODEL_PATH", "models/classifier.json")),
            ocr_enabled=os.getenv("PIF_OCR", "0") == "1",
            log_dir=Path(os.getenv("PIF_LOG_DIR", "logs")),
            log_level=os.getenv("PIF_LOG_LEVEL", "DEBUG").upper(),
            log_max_bytes=int(os.getenv("PIF_LOG_MAX_BYTES", str(10 * 1024 * 1024))),
            log_backup_count=int(os.getenv("PIF_LOG_BACKUP_COUNT", "5")),
            log_console=os.getenv("PIF_LOG_CONSOLE", "1") == "1",
            log_content=os.getenv("PIF_LOG_CONTENT", "0") == "1",
            log_content_max_chars=int(os.getenv("PIF_LOG_CONTENT_MAX_CHARS", "4096")),
            log_simple=os.getenv("PIF_LOG_SIMPLE", "1") == "1",
            log_script_details=os.getenv("PIF_LOG_SCRIPT_DETAILS", "1") == "1",
            log_scan_id=os.getenv("PIF_LOG_SCAN_ID", "1") == "1",
            block_threshold=block_threshold,
            hard_block_threshold=hard_block_threshold,
            sanitize_threshold=sanitize_threshold,
            quarantine_enabled=os.getenv("PIF_QUARANTINE", "1") == "1",
            quarantine_dir=Path(os.getenv("PIF_QUARANTINE_DIR", "quarantine")),
            report_db_enabled=os.getenv("PIF_REPORT_DB", "1") == "1",
            report_db_path=Path(os.getenv("PIF_REPORT_DB_PATH", "data/report.db")),
            pdf_max_pages=int(os.getenv("PIF_PDF_MAX_PAGES", "100")),
            zip_entry_limit=int(os.getenv("PIF_ZIP_ENTRY_LIMIT", "100")),
            docx_max_uncompressed_bytes=int(
                os.getenv("PIF_DOCX_MAX_UNCOMPRESSED_BYTES", str(50 * 1024 * 1024))
            ),
            zip_expansion_limit=int(os.getenv("PIF_ZIP_EXPANSION_LIMIT", "100")),
            image_pixel_limit=int(os.getenv("PIF_IMAGE_PIXEL_LIMIT", str(20_000_000))),
            attachment_max_depth=int(os.getenv("PIF_ATTACHMENT_MAX_DEPTH", "2")),
            max_extracted_segments=int(os.getenv("PIF_MAX_EXTRACTED_SEGMENTS", "2000")),
            scan_concurrency=int(os.getenv("PIF_SCAN_CONCURRENCY", "4")),
            parser_concurrency=int(os.getenv("PIF_PARSER_CONCURRENCY", "2")),
            policy_config=policy_config,
        )
