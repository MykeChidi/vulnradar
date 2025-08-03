# vulnscan/utils/logger.py - Logging Scan Output

import logging
import sys
from colorama import Fore, Style

def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create a logger that prints colored output to stderr.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    fmt = (
        f"%(asctime)s {Fore.GREEN}[%(levelname)s]{Style.RESET_ALL} "
        "%(message)s"
    )
    formatter = logging.Formatter(fmt, datefmt="%d-%m-%Y %H:%M:%S")
    handler.setFormatter(formatter)

    # avoid duplicate handlers
    if not logger.handlers:
        logger.addHandler(handler)
    return logger