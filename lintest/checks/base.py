"""Check runner helpers.

The single guarantee of this module: a crashing check function can never
take down the whole run.  :func:`run_check` wraps any callable and turns
an unexpected exception into an ERROR :class:`CheckResult`.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List

from lintest.models import CheckResult, error

logger = logging.getLogger(__name__)


def run_check(
    name: str,
    func: Callable[..., List[CheckResult]],
    *args: Any,
    **kwargs: Any,
) -> List[CheckResult]:
    """Run *func* and guarantee a list of results.

    Args:
        name: Check area name used in the ERROR result (e.g. ``system``).
        func: The check function; must return an iterable of CheckResult.
        *args: Positional arguments passed through to *func*.
        **kwargs: Keyword arguments passed through to *func*.

    Returns:
        The check's results as a list, or a single ERROR result when it
        raised.  Check functions may return a list *or* a single
        CheckResult (scalar-returning checks are normalised here).
    """
    try:
        results = func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: never crash the run
        logger.exception("Check %s crashed", name)
        return [
            error(
                name,
                f"check crashed: {type(exc).__name__}: {exc}",
                subject=name,
            )
        ]
    if results is None:
        return []
    if isinstance(results, CheckResult):
        return [results]
    return list(results)
