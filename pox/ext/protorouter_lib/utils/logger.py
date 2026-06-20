from ext.protorouter_lib.utils.colors import *

from pox.core import core

class Logger:
    logger = core.getLogger()

    @staticmethod
    def info_red(text: str) -> None:
        Logger.logger.info(f"{RED}{text}{RESET}")

    
    @staticmethod
    def info_yellow(text: str) -> None:
        Logger.logger.info(f"{YELLOW}{text}{RESET}")

    @staticmethod
    def info_cyan(text: str) -> None:
        Logger.logger.info(f"{CYAN}{text}{RESET}")

    
    @staticmethod
    def info_green(text: str) -> None:
        Logger.logger.info(f"{GREEN}{text}{RESET}")

    @staticmethod
    def warn(text: str) -> None:
        Logger.logger.warning(text)

    @staticmethod
    def error(text: str) -> None:
        Logger.logger.error(text)
