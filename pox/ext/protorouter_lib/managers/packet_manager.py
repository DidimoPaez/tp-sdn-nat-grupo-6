from __future__ import annotations
from typing import TYPE_CHECKING

from ext.protorouter_lib.utils.logger import Logger
from pox.pox.lib.packet.ethernet import ethernet

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.arp_manager import ArpManager
    from ext.protorouter_lib.managers.nat_manager import NatManager

class PacketManager:
    def __init__(self, arp_manager: ArpManager, nat_manager: NatManager):
        self.arp_manager: ArpManager = arp_manager
        self.nat_manager: NatManager = nat_manager

    def handle_packet_in(self, event):
        Logger.info_red(f"_handle_PacketIn has been called {self.global_counter} times")
        self.global_counter += 1

        packet: ethernet = event.parsed

        if not packet.parsed:
            Logger.warn("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if packet.type == ethernet.IP_TYPE:
            self.nat_manager.handle_ip(event)
        elif packet.type == ethernet.ARP_TYPE:
            self.arp_manager.handle_arp(event)
        else:
            Logger.info_red(f"Packet ignored: protocol received: {packet.type}.")
