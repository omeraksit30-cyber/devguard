"""Entry point: python -m devguard"""

import logging
import sys

import uvicorn

from .config import ConfigError, get_settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        settings = get_settings()
    except ConfigError as exc:
        print(f"DevGuard configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    from .app import create_app

    print(f"DevGuard running at http://{settings.host}:{settings.port}")
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info",
                server_header=False, access_log=False)


if __name__ == "__main__":
    main()
