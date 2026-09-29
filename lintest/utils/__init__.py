"""Small shared helpers: logging setup and subprocess wrappers."""

from lintest.utils.logging_setup import setup_logging
from lintest.utils.shell import run_command

__all__ = ["setup_logging", "run_command"]
