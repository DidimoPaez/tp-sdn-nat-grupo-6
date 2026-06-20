from ext.protorouter_lib.utils.colors import *

from pox.core import core

class Logger:
    logger = core.getLogger()

    def info_red(self, text: str) -> None:
        Logger.logger.info(f"{RED}{text}{RESET}")

    def info_yellow(self, text: str) -> None:
        Logger.logger.info(f"{YELLOW}{text}{RESET}")

    def info_cyan(self, text: str) -> None:
        Logger.logger.info(f"{CYAN}{text}{RESET}")

    def info_green(self, text: str) -> None:
        Logger.logger.info(f"{GREEN}{text}{RESET}")

    def warn(self, text: str) -> None:
        Logger.logger.warning(text)

    def error(self, text: str) -> None:
        Logger.logger.error(text)
