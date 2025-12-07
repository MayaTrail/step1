"""
supply a basic logging configuration across multiple py simulations
"""

import sys
import logging
from colorama import Fore, Style

def get_logger(name: str, level=logging.INFO, log_file:str=None):
    """
    return a logger object with default configuration
    """

    try:
        logger = logging.getLogger(name or "step1-logging")
        logger.setLevel(logging.INFO)

        stream_handler = logging.StreamHandler(sys.stdout)
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            f"{Fore.YELLOW} '%(asctime)s {Style.RESET_ALL} - {Fore.CYAN} %(name)s {Style.RESET_ALL} - {Fore.LIGHTGREEN_EX} %(levelname)s {Style.RESET_ALL} - %(message)s"
        )
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

        # add another handler to the logger based on log_file param
        if log_file:
            file_handler = logging.FileHandler(log_file, mode="a")
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger
    except Exception as err:
        raise Exception(f"Can't set logger! Reason: {err.__str__()}")