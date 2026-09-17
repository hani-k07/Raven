import logging
import sys
from pathlib import Path

# Log configuration
LOG_FILE = Path(__file__).parent / "raven.log"

def setup_logger(name: str = "RAVEN"):
    """Configures a professional logger for the system."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if logger is retrieved multiple times
    if not logger.handlers:
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Console Handler
        console_h = logging.StreamHandler(sys.stdout)
        console_h.setFormatter(formatter)
        logger.addHandler(console_h)

        # File Handler
        file_h = logging.FileHandler(LOG_FILE, encoding='utf-8')
        file_h.setFormatter(formatter)
        logger.addHandler(file_h)

    return logger

# Global logger instance
log = setup_logger()
