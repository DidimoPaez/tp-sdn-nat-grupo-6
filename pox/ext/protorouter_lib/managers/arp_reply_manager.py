from __future__ import annotations
from typing import TYPE_CHECKING

from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger
from pox.pox.lib.packet.arp import arp
from pox.pox.lib.packet.ethernet import ethernet
from pox.pox.openflow import PacketIn

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.arp_table_manager import ArpTableManager
    from ext.protorouter_lib.managers.flow_manager import FlowManager
    from ext.protorouter_lib.managers.nat_table_manager import NatTableManager
    from ext.protorouter_lib.managers.packet_forward_manager import PacketForwardManager


class ArpReplyManager:
    def __init__(self, arp_table_manager: ArpTableManager, nat_table_manager: NatTableManager, packet_forward_manager: PacketForwardManager, flow_manager: FlowManager):
        self.cfg: ControllerConfig = ControllerConfig.get()
        self.arp_table_manager: ArpTableManager = arp_table_manager
        self.nat_table_manager: NatTableManager = nat_table_manager
        self.packet_forward_manager: PacketForwardManager = packet_forward_manager
        self.flow_manager: FlowManager = flow_manager

    def handle_packet_arp_reply(self, event: PacketIn):
        Logger.info_yellow("Handling an ARP Reply")
        packet: ethernet = event.parsed
        arp_packet: arp = packet.payload

        host_public_ip = arp_packet.protosrc
        host_public_mac = arp_packet.hwsrc
        openflow_public_port = event.port

        self.arp_table_manager.learn_arp_entry(openflow_public_port, host_public_ip, host_public_mac)

        pending_list = self.arp_table_manager.pop_pending(host_public_ip)

        if len(pending_list) == 0:
            Logger.info_yellow(f"No pending packets for {host_public_ip}")
            return

        self.drain_pending_packets(pending_list, host_public_mac, openflow_public_port)

    def drain_pending_packets(self, pending_packets, host_public_mac, openflow_public_port):
        for pending_packet in pending_packets:
            nat_entry = pending_packet.nat_entry

            if nat_entry is None:
                Logger.info_red("[ERROR] Pending packet without NAT entry")
                continue

            self.nat_table_manager.mark_installed(nat_entry, host_public_mac, openflow_public_port)
            self.flow_manager.install_flows(nat_entry)

            Logger.info_green(f"NAT entry completed:\n{nat_entry}")

            self.packet_forward_manager.forward_packet(pending_packet)
