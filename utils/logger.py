# Centralized logging configuration
import logging
import os
import datetime

def setup_logger(name, log_file="logs/application.log", level=logging.DEBUG):
    # Prepend date and time to the log file name
    os.makedirs(os.path.dirname(log_file), exist_ok=True)


    
    # # Console handler
    # console_handler = logging.StreamHandler()
    # console_handler.setFormatter(formatter)
    # logger.addHandler(console_handler)

    logger = logging.getLogger(name)
    if not logger.hasHandlers():  # Avoid adding multiple handlers
        logger.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # File handler
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

# Create a single logger instance for the entire application
app_logger = setup_logger(name="ApplicationLogger")