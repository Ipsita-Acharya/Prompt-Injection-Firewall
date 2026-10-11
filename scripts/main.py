import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import os
import secrets
from pathlib import Path

import uvicorn

from pif.api import create_app
from pif.observability import configure_logging, logger
from pif.settings import Settings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the loopback-only PIF API")
    parser.add_argument(
        "--init-token",
        action="store_true",
        help="Create a local token file without displaying its value",
    )
    args = parser.parse_args()
    settings = Settings.load()
    configure_logging(settings)
    logger.info("main.started", extra={"event_fields": dict(mode="initialize_token" if args.init_token else "serve_api")})
    if args.init_token:
        token_file = Path(".pif-token")
        try:
            with token_file.open("x", encoding="utf-8") as handle:
                handle.write(secrets.token_urlsafe(32))
            token_file.chmod(0o600)
            logger.info("main.token_created", extra={"event_fields": dict()})
            print("Created .pif-token. Protect its Windows file permissions; do not share it.")
        except FileExistsError:
            logger.info("main.token_already_exists", extra={"event_fields": dict()})
            print("Token file already exists; not overwritten.")
        raise SystemExit(0)
    app = create_app(settings)
    port = int(os.getenv("PIF_PORT", "8000"))
    # Loopback by default (the documented posture); PIF_HOST overrides for
    # container deployments where the API must be reachable from outside.
    host = os.getenv("PIF_HOST", "127.0.0.1")
    logger.info("main.server_starting", extra={"event_fields": dict(host=host, port=port)})
    uvicorn.run(app, host=host, port=port, access_log=False)
    logger.info("main.completed", extra={"event_fields": dict()})
