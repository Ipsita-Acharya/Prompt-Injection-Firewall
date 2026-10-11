"""UI server: hosts the saved GenWizard / ChatGPT / Gemini pages on localhost and
proxies prompt + attachment requests to the local PIF API (scripts/main.py on port 8000).

Run:  .venv/Scripts/python.exe UI_AI_Replica/server.py   (UI on http://127.0.0.1:8080)
The PIF API must be running separately:  .venv/Scripts/python.exe scripts/main.py
"""

import json
import logging
import os
import sys
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = BASE_DIR / "templates"
PROJECT_ROOT = BASE_DIR.parent
PIF_API = os.getenv("PIF_URL", "http://127.0.0.1:8000")
UI_PORT = int(os.getenv("PIF_UI_PORT", "8080"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ui_replica")

# page path -> (html file, asset folder, asset-folder spellings to rewrite to ./assets/,
#               inject the rebuild stylesheet for pages whose snapshot lost its styles)
PAGES = {
    "genwizard": (
        "GenWizard.html",
        "GenWizard_files",
        ["GenWizard_files/"],
        True,
    ),
    "chatgpt": (
        "ChatGPT_ Chat, Work, Create & Code with AI.html",
        "ChatGPT_ Chat, Work, Create & Code with AI_files",
        [
            "ChatGPT_ Chat, Work, Create &amp; Code with AI_files/",
            "ChatGPT_ Chat, Work, Create & Code with AI_files/",
        ],
        False,
    ),
    "gemini": (
        "Google Gemini.html",
        "Google Gemini_files",
        ["Google%20Gemini_files/", "Google Gemini_files/"],
        False,
    ),
}


def load_token() -> str:
    token = os.getenv("PIF_API_TOKEN", "")
    if not token:
        token_file = PROJECT_ROOT / ".pif-token"
        if token_file.is_file():
            token = token_file.read_text(encoding="utf-8").strip()
    return token


def render_page(filename: str, asset_spellings: list[str], extra_css: bool) -> str:
    html = (TEMPLATES / filename).read_text(encoding="utf-8")
    for spelling in asset_spellings:
        html = html.replace(spelling, "assets/")
    inject = '<script src="/pif-client.js"></script>'
    if extra_css:
        # GenWizard page: rebuild stylesheet + layout script (after pif-client so
        # the wired prompt box moves with the restructure)
        inject = (
            '<link rel="stylesheet" href="/genwizard.css">'
            + inject
            + '<script src="/genwizard.js"></script>'
        )
    position = html.lower().rfind("</body>")
    if position == -1:
        position = len(html)
    html = html[:position] + inject + html[position:]
    return html


def create_app() -> FastAPI:
    app = FastAPI(title="PIL UI Replica", docs_url=None, redoc_url=None)
    token = load_token()
    if not token:
        log.warning("No PIF_API_TOKEN found; set it or create .pif-token (scripts/main.py --init-token)")

    for route, (filename, asset_dir, spellings, extra_css) in PAGES.items():
        app.mount(f"/{route}/assets", StaticFiles(directory=TEMPLATES / asset_dir), name=route)

        def page_handler(filename=filename, spellings=spellings, extra_css=extra_css):
            return HTMLResponse(render_page(filename, spellings, extra_css))

        app.get(f"/{route}/", name=route)(page_handler)

    @app.get("/genwizard.css")
    def genwizard_css():
        return Response(
            (BASE_DIR / "genwizard.css").read_text(encoding="utf-8"),
            media_type="text/css",
        )

    @app.get("/genwizard.js")
    def genwizard_js():
        return Response(
            (BASE_DIR / "genwizard.js").read_text(encoding="utf-8"),
            media_type="application/javascript",
        )

    @app.get("/")
    def index():
        links = "".join(
            f'<a href="/{route}/">{title}</a>'
            for route, title in [
                ("genwizard", "GenWizard"),
                ("chatgpt", "ChatGPT"),
                ("gemini", "Google Gemini"),
            ]
        )
        return HTMLResponse(
            "<!DOCTYPE html><html><head><title>PIL UI Replica</title>"
            "<style>body{font-family:Segoe UI,sans-serif;background:#111;color:#eee;"
            "display:flex;flex-direction:column;align-items:center;justify-content:center;"
            "height:100vh;margin:0}a{display:block;margin:10px;padding:18px 40px;font-size:20px;"
            "background:#1f6feb;color:#fff;text-decoration:none;border-radius:10px;width:260px;"
            "text-align:center}a:hover{background:#388bfd}</style></head>"
            f"<body><h1>PIL UI Replica</h1>{links}</body></html>"
        )

    @app.get("/pif-client.js")
    def client_script():
        return Response(
            (BASE_DIR / "pif_client.js").read_text(encoding="utf-8"),
            media_type="application/javascript",
        )

    @app.post("/pif/scan")
    async def scan(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)

        prompt = str(body.get("prompt") or "")[:250_000]
        files = []
        for item in list(body.get("files") or [])[:10]:
            data = str(item.get("data_base64") or "")
            files.append(
                {
                    "name": str(item.get("name") or "attachment")[:255],
                    "type": str(item.get("type") or "application/octet-stream")[:100],
                    "data_base64": data[:14_000_000],
                }
            )

        if not token:
            return JSONResponse(
                {"ok": False, "error": "PIF API token not configured on the UI server"},
                status_code=503,
            )

        payload = {"user_prompt": prompt, "files": files}
        headers = {
            "Authorization": f"Bearer {token}",
            "X-PIF-Trace-ID": __import__("uuid").uuid4().hex,
        }
        try:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as client:
                response = await client.post(
                    PIF_API.rstrip("/") + "/v1/scan", json=payload, headers=headers, timeout=60
                )
        except httpx.HTTPError as error:
            log.error("PIF API unreachable: %s", type(error).__name__)
            return JSONResponse(
                {"ok": False, "error": f"PIF API unreachable at {PIF_API}"}, status_code=502
            )

        try:
            result = response.json()
        except json.JSONDecodeError:
            result = None
        log.info("scan decision=%s status=%s http=%s files=%d",
                 (result or {}).get("decision"), (result or {}).get("status"),
                 response.status_code, len(files))
        return JSONResponse({"ok": response.is_success, "http_status": response.status_code, "result": result})

    return app


if __name__ == "__main__":
    log.info("UI server starting on http://127.0.0.1:%d (PIF API: %s)", UI_PORT, PIF_API)
    uvicorn.run(create_app(), host="127.0.0.1", port=UI_PORT, access_log=False)
