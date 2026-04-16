"""
Flask application factory.
"""

import logging
from flask import Flask
from config import SECRET_KEY, SERVER_HOST, SERVER_PORT
from server.security import add_security_headers
from server.routes import register_routes
from server.auth import ensure_users_table

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("scms.app")


def create_app() -> Flask:
    app = Flask(__name__, template_folder=None)

    app.config["SECRET_KEY"]              = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"]      = 16 * 1024 * 1024
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"]   = False    # set True when TLS enabled
    app.config["PERMANENT_SESSION_LIFETIME"] = 8 * 3600

    app.after_request(add_security_headers)
    register_routes(app)

    with app.app_context():
        try:
            ensure_users_table()
        except Exception as e:
            log.warning("Could not ensure users table: %s", e)

    return app


app = create_app()

if __name__ == "__main__":
    log.warning("Dev mode — use run_server.py for production")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)
