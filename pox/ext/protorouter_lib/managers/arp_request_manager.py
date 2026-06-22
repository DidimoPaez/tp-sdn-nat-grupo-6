from __future__ import annotations
from typing import TYPE_CHECKING

from ext.protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.models.pending_packet import PendingPacket
from ext.protorouter_lib.utils.logger import Logger
from pox.pox.lib.addresses import IPAddr
from pox.pox.lib.packet.ethernet import ethernet
from pox.pox.openflow import PacketIn

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.arp_table_manager import ArpTableManager
    from ext.protorouter_lib.managers.flow_info_manager import FlowInfoManager
    from ext.protorouter_lib.managers.nat_table_manager import NatTableManager
    from ext.protorouter_lib.openflow_sender import OpenFlowSender
    from ext.protorouter_lib.managers.pending_packet_manager import PendingPacketManager


class ArpRequestManager:
    def __init__(self, flow_info_manager: FlowInfoManager, arp_table_manager: ArpTableManager, nat_table_manager: NatTableManager, pending_packet_manager: PendingPacketManager, of_sender: OpenFlowSender):
        self.cfg: ControllerConfig = ControllerConfig.get()
        self.flow_info_manager: FlowInfoManager = flow_info_manager
        self.arp_table_manager: ArpTableManager = arp_table_manager
        self.nat_table_manager: NatTableManager = nat_table_manager
        self.pending_packet_manager: PendingPacketManager = pending_packet_manager
        self.of_sender: OpenFlowSender = of_sender

    def add_pending_packet(self, target_ip, pending_packet: PendingPacket):
        if not self.pending_packet_manager.contains_binded(target_ip):
            self.of_sender.make_an_arp_request(
                target_ip, PUBLIC_PORT, self.cfg.nat_public_mac, self.cfg.nat_public_ip
            )
        self.pending_packet_manager.bind(pending_packet, target_ip)

    def ask_for_mac_to_public_host(self, event: PacketIn):
        packet: ethernet = event.parsed
        ip_packet = packet.payload
        target_ip = ip_packet.dstip

        # Validar que la IP no sea una IP de la red privada
        if IPAddr(target_ip).inNetwork(self.cfg.nat_private_net, self.cfg.nat_private_mask):
            Logger.info_red("[ERROR] MAC address Searchs just for private hosts")
            return

        flow_info = self.flow_info_manager.extract_flow_info(packet, event.port)
        if flow_info is None:
            return

        nat_entry = self.nat_table_manager.get(flow_info)
        if nat_entry is not None:
            Logger.info_yellow(f"Paquete repetido para un flujo ya en curso (estado={nat_entry.state}), se descarta",)
            return

        nat_entry = self.nat_table_manager.put_and_get(flow_info)

        Logger.info_yellow(f"New NAT Entry (PENDING):\n {nat_entry}\n")

        pending_packet = PendingPacket(event.port, event.ofp.data, nat_entry)
        self.add_pending_packet(target_ip, pending_packet)
