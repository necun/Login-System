import logging
from logging.handlers import TimedRotatingFileHandler

class logger_method:
    def setup_logger(self):
        # Initialize logger
        logger = logging.getLogger("my_logger")
        logger.setLevel(logging.INFO)  # Set default log level to INFO

        # Define log formatter
        log_formatter = logging.Formatter("%(asctime)s,%(levelname)s,%(message)s")

        # Configure file handler
        file_handler = TimedRotatingFileHandler("renote_logins_logs", when='midnight', interval=1, backupCount=90)
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)  # Set file handler log level to ERROR

        # Add file handler to logger
        logger.addHandler(file_handler)

        return logger
