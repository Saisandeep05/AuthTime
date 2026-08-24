"""
AuthTime Structured Logging.

Provides a pre-configured logger for the authtime package.
Default level is WARNING (silent in normal operation).
Set AUTHTIME_LOG_LEVEL=DEBUG for verbose diagnostic output.

Usage:
    from authtime.logging import logger
    logger.debug("Diagnostic message: %s", detail)
    logger.warning("Something unexpected: %s", err)
"""

import logging
import os

_level_name = os.environ.get("AUTHTIME_LOG_LEVEL", "WARNING").upper()
_level = getattr(logging, _level_name, logging.WARNING)

logger = logging.getLogger("authtime")
logger.setLevel(_level)

if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setLevel(_level)
    _formatter = logging.Formatter(
        "[%(levelname)s] authtime.%(module)s: %(message)s"
    )
    _handler.setFormatter(_formatter)
    logger.addHandler(_handler)
