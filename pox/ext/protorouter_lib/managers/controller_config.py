from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pox.ext.protorouter_lib.managers.controller_config import ControllerConfig

from ext.protorouter_lib.constants import *

class ControllerConfig:
    instance: ControllerConfig | None = None

    def __init__(self):
        self.nat_private_net = PRIVATE_SUBNET
        self.nat_private_mask = PRIVATE_MASK
        self.nat_private_ip = PRIVATE_IP
        self.nat_public_ip = PUBLIC_IP
        self.nat_private_mac = PRIVATE_MAC
        self.nat_public_mac = PUBLIC_MAC

    @staticmethod
    def get() -> ControllerConfig:
        if ControllerConfig.instance is None:
            ControllerConfig.instance = ControllerConfig()
        return ControllerConfig.instance
