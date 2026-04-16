"""
run_server.py — Secure Continuous Monitoring System
Production server launcher.  Wraps Flask via Werkzeug's make_server so
SIGTERM drains requests and stops cleanly — no stack traces on shutdown.

"""

import signal
import sys
import logging
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

_handler = RotatingFileHandler(
    LOG_DIR / "server.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))
logging.basicConfig(level=logging.INFO, handlers=[_handler, logging.StreamHandler(sys.stdout)])
log = logging.getLogger("scms.server")

_shutdown = threading.Event()


def _handle_shutdown(sig, frame):
    log.info("Shutdown signal received — stopping server …")
    _shutdown.set()


signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT,  _handle_shutdown)

from config import SERVER_HOST, SERVER_PORT, TLS_CERT, TLS_KEY
from app import create_app


def main():
    flask_app = create_app()

    try:
        from werkzeug.serving import make_server
    except ImportError:
        log.error("Werkzeug not installed — pip install flask")
        sys.exit(1)

    ssl_context = None
    if TLS_CERT and TLS_KEY:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(TLS_CERT, TLS_KEY)
        log.info("TLS enabled — cert: %s", TLS_CERT)

    server = make_server(SERVER_HOST, SERVER_PORT, flask_app, ssl_context=ssl_context)
    server.timeout = 1

    proto = "https" if ssl_context else "http"
    log.info("SCMS Server listening on %s://%s:%d", proto, SERVER_HOST, SERVER_PORT)

    srv_thread = threading.Thread(target=_serve, args=(server,), daemon=True, name="http-server")
    srv_thread.start()

    log.info("Dashboard → %s://localhost:%d", proto, SERVER_PORT)
    _shutdown.wait()

    log.info("Shutting down HTTP server …")
    server.shutdown()
    srv_thread.join(timeout=8)
    log.info("Server stopped.")
    sys.exit(0)


def _serve(server):
    try:
        server.serve_forever()
    except Exception:
        pass


if __name__ == "__main__":
    main()
