#!/usr/bin/env python3
"""Build wizard/hiddenforge-wizard.html: one self-contained file.

The script and the stylesheet are inlined and pinned in the page's
Content-Security-Policy by SHA-256, so the browser runs exactly this code and
nothing else, from file:// or anywhere. `connect-src 'none'` and
`form-action 'none'` mean the page cannot send anything anywhere, even if its
code were changed (a changed script no longer matches its hash and is refused).

    python3 wizard/build.py           # writes wizard/hiddenforge-wizard.html
    python3 wizard/build.py --check   # exit 1 if the committed file is stale
"""
import base64
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "hiddenforge-wizard.html"


def b64sha256(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()


def build() -> str:
    render = (HERE / "render.js").read_text(encoding="utf-8")
    version = render.split('var VERSION = "', 1)[1].split('"', 1)[0]
    js = "\n" + render + "\n" + (HERE / "ui.js").read_text(encoding="utf-8") + "\n"
    css = "\n" + (HERE / "style.css").read_text(encoding="utf-8") + "\n"
    if "</script" in js.lower() or "</style" in css.lower():
        raise SystemExit("refusing: a closing tag inside inlined code")
    csp = ("default-src 'none'; "
           f"script-src 'sha256-{b64sha256(js)}'; "
           f"style-src 'sha256-{b64sha256(css)}'; "
           "img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; "
           "object-src 'none'")
    html = (HERE / "index.src.html").read_text(encoding="utf-8")
    return (html.replace("@CSP@", csp).replace("@VERSION@", version)
            .replace("<style>@CSS@</style>", f"<style>{css}</style>")
            .replace("<script>@JS@</script>", f"<script>{js}</script>"))


if __name__ == "__main__":
    page = build()
    if "--check" in sys.argv:
        ok = OUT.exists() and OUT.read_text(encoding="utf-8") == page
        print("wizard is current" if ok else "wizard/hiddenforge-wizard.html is stale: run wizard/build.py")
        sys.exit(0 if ok else 1)
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT} ({len(page)} bytes), sha256 {hashlib.sha256(page.encode()).hexdigest()}")
