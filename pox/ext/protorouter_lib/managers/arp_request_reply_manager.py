from __future__ import annotations
from typing import TYPE_CHECKING

from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger
from pox.pox.lib.packet.arp import arp
from pox.pox.lib.packet.ethernet import ethernet
from pox.pox.openflow import PacketIn

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.arp_table_manager import ArpTableManager
    from ext.protorouter_lib.openflow_sender import OpenFlowSender


class ArpRequestReplyManager:
    def __init__(self, arp_table_manager: ArpTableManager, of_sender: OpenFlowSender):
        self.cfg: ControllerConfig = ControllerConfig.get()
        self.arp_table_manager: ArpTableManager = arp_table_manager
        self.of_sender: OpenFlowSender = of_sender

    def get_mac_for_given_ip(self, ip):
        mac_response = None
        if ip == self.cfg.nat_private_ip:
            mac_response = self.cfg.nat_private_mac
        if ip == self.cfg.nat_public_ip:
            mac_response = self.cfg.nat_public_mac
        return mac_response

    def handle_packet_arp_request(self, event: PacketIn):
        Logger.info_yellow("Handling an ARP Request")
        packet: ethernet = event.parsed
        arp_packet: arp = packet.payload
        in_port = event.port
        addr_asked = packet.payload.protodst

        self.arp_table_manager.learn_arp_entry(in_port, packet.payload.protosrc, packet.payload.hwsrc)
        mac_response = self.get_mac_for_given_ip(addr_asked)

        if mac_response is None:
            Logger.info_yellow(
                f"ARP request ignored: {arp_packet.protosrc} asked for {addr_asked}, "
                f"This IP does not belong to Switch NAT",
            )
            return

        self.of_sender.make_an_arp_reply(arp_packet, mac_response, addr_asked, in_port)
