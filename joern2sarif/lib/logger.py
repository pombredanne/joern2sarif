import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)
LOG = logging.getLogger(__name__)

# Set logging level
if os.getenv("SCAN_DEBUG_MODE") == "debug":
    LOG.setLevel(logging.DEBUG)

DEBUG = logging.DEBUG
