"""Runtime oracle: MULTIPLE top-level side-effect calls + env reads + registry.

Pins the side-effect MERGE: three module-level call statements must merge into
ONE `<rel>:module` runtime node (not three), with their call names unioned into
side_effects, and module-level os.environ reads attached to depends_on_env.

Also pins decorator_registry (@app.route) and a background-task spawn inside an
init-style function (bootstrap).
"""
from __future__ import annotations

import os

app = object()
configure_logging = print
register_plugins = print
warm_cache = print

# Three top-level side-effect calls -> MUST merge into one :module node.
configure_logging("init")
register_plugins()
warm_cache()

# Module-level env reads -> depends_on_env on the :module node.
DEBUG = os.getenv("DEBUG")
REGION = os.environ.get("AWS_REGION")


@app.route("/health")  # type: ignore[attr-defined]
def health():
    return "ok"


def bootstrap():
    import threading

    # assign form: pins _background_task_tag detection inside a scanned func
    worker_thread = threading.Thread(target=warm_cache)
    worker_thread.start()
    token = os.getenv("API_TOKEN")
    return token
