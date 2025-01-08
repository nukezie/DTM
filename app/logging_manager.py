"""
Logging Manager Module
Centralizes logging configuration for the entire application.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
            
        if hasattr(record, "extra"):
            log_obj.update(record.extra)
            
        return json.dumps(log_obj)

def setup_logging(log_level: str = "INFO") -> None:
    """
    Set up application-wide logging configuration.
    Writes structured JSON logs to file only, no terminal output.
    
    Args:
        log_level: The logging level to use (default: "INFO")
    """
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add JSON file handler
    json_handler = logging.FileHandler(log_dir / "dtm.json")
    json_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(json_handler)
    
    # Set logging levels for noisy modules
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    
    # Log startup
    logger = logging.getLogger(__name__)
    logger.info("Logging system initialized", extra={
        "config": {
            "log_level": log_level,
            "log_file": str(log_dir / "dtm.json"),
            "format": "JSON"
        }
    }) 