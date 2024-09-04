import logging
import pdb

# Set up the logging configuration
LOG_FILE = 'var/ossec/logs/framework.log'

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,  # Set to DEBUG level to capture all logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_debug(message, debugger_name=None):
    """
    Logs a debug message. If debugger_name is provided, it is included in the log.
    Optionally starts a pdb debugger.
    
    Args:
        message (str): The debug message to log.
        debugger_name (str, optional): The name to include in the log. Defaults to None.
    """
    if debugger_name:
        message = f"[{debugger_name}] {message}"
    
    logging.debug(message)
    
    # Optionally start the debugger
    if debugger_name:
        pdb.set_trace()

def log_info(message):
    """
    Logs an info message.
    
    Args:
        message (str): The info message to log.
    """
    logging.info(message)

def log_warning(message):
    """
    Logs a warning message.
    
    Args:
        message (str): The warning message to log.
    """
    logging.warning(message)

def log_error(message):
    """
    Logs an error message.
    
    Args:
        message (str): The error message to log.
    """
    logging.error(message)

def log_critical(message):
    """
    Logs a critical message.
    
    Args:
        message (str): The critical message to log.
    """
    logging.critical(message)