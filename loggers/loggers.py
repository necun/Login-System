import logging
from logging.handlers import RotatingFileHandler

class logger:
    def logger():
        a="5"
        logger = logging.getLogger("my_logger")
        logger.setLevel(logging.INFO)
        log_formatter  = logging.Formatter("%(asctime)s,%(levelname)s,%(message)s")
        file_handler = RotatingFileHandler("renote_logins_logs", maxBytes=1, backupCount=90)
        file_handler.setFormatter(log_formatter)
        handler_variable=logger.addHandler(file_handler)
        return handler_variable