"""Logging configuration: stderr console + rotating file.

Console logs always go to **stderr** so that stdout stays clean for the
JSON output mode and for piping.  The file handler is a
:class:`~logging.handlers.RotatingFileHandler`; if the log directory is
not writable the handler is skipped with a warning instead of crashing.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from lintest.config import LoggingConfig

_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(cfg: LoggingConfig, verbose: bool = False) -> None:
    """Configure the ``lintest`` logger tree.

    Args:
        cfg: Validated logging section of the config.
        verbose: When True force DEBUG on all handlers (--verbose flag).
    """
    root = logging.getLogger("lintest")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    level = logging.DEBUG if verbose else getattr(logging, cfg.level, logging.INFO)

    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(level)
    console.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    root.addHandler(console)

    if cfg.file:
        try:
            log_path = Path(cfg.file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                log_path, maxBytes=cfg.max_bytes, backupCount=cfg.backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
            root.addHandler(file_handler)
        except OSError as exc:
            root.warning("file logging disabled (%s): %s", cfg.file, exc)

    # Third-party libraries can be chatty on DEBUG; keep them quiet.
    for noisy in ("urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
