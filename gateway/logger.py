import logging
import os

log_path = "logs/gateway.log"

# ensure logs directory exists
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger()