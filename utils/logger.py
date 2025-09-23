# vulnscan/utils/logger.py - Logging Scan Output

import logging
import os
import sys
from datetime import datetime
from colorama import Fore, Style

def setup_logger(name: str, level: int = logging.INFO, log_to_file: bool = True, scanner_specific: bool = False) -> logging.Logger:
    """
    Create a logger that prints colored output to stderr and optionally logs to a file.
    
    Args:
        name: The name of the logger
        level: The logging level
        log_to_file: Whether to also log output to a file (default: True)
        scanner_specific: Whether this is a scanner-specific logger (default: False)
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Console handler with colored output
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_fmt = (
        f"%(asctime)s {Fore.GREEN}[%(levelname)s]{Style.RESET_ALL} "
        "%(message)s"
    )
    console_formatter = logging.Formatter(console_fmt, datefmt="%d-%m-%Y %H:%M:%S")
    console_handler.setFormatter(console_formatter)

    # avoid duplicate handlers
    if not logger.handlers:
        logger.addHandler(console_handler)

        # Add file handler if requested
        if log_to_file:
            # Create scan_results directory if it doesn't exist
            log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scan_results')
            os.makedirs(log_dir, exist_ok=True)
            
            # Create timestamp for the current scan
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if scanner_specific:
                # For scanner-specific logs, create a subdirectory for the current scan
                scan_dir = os.path.join(log_dir, f'scan_{timestamp}')
                os.makedirs(scan_dir, exist_ok=True)
                # Create scanner-specific log file
                log_file = os.path.join(scan_dir, f'{name.lower()}.log')
            else:
                # Create main scan log file
                log_file = os.path.join(log_dir, f'scan_{timestamp}.log')
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            
            # File output without colors
            file_fmt = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
            file_formatter = logging.Formatter(file_fmt, datefmt="%d-%m-%Y %H:%M:%S")
            file_handler.setFormatter(file_formatter)
            
            logger.addHandler(file_handler)

    return logger