"""Logging configuration for DeployGuard."""

import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (usually __name__)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Only configure if no handlers exist
    if not logger.handlers:
        # Set level
        log_level = getattr(logging, level.upper() if level else "INFO")
        logger.setLevel(log_level)

        # Create console handler with formatting
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)

        # Create formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger
