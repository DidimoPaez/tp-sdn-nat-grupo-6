from __future__ import annotations
from typing import TYPE_CHECKING

from ext.protorouter_lib.managers.controller_config import ControllerConfig

if TYPE_CHECKING:
    from ext.protorouter_lib.openflow_sender import OpenFlowSender

class PacketForwardManager:
    def __init__(self, of_sender: OpenFlowSender):
        self.cfg: ControllerConfig = ControllerConfig.get()
        self.of_sender: OpenFlowSender = of_sender

    def forward_packet(self, packet):
        nat_entry = packet.nat_entry
        self.of_sender.forward_of_data(
            packet.raw_packet,
            self.cfg.nat_public_mac,
            self.cfg.nat_public_ip,
            nat_entry.nat_public_port,
            nat_entry.public_openflow_port,
            nat_entry.host_public_mac,
            nat_entry.host_public_ip,
            nat_entry.host_public_port,
            nat_entry.host_private_ip,
            nat_entry.host_private_port,
        )
