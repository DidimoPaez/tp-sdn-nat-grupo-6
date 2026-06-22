"""
NatManager

Por ahora sólo se extrajo de ProtoRouter la asignación de puertos
públicos (lo que antes era self.next_nat_public_port / self.assigned_ports),
para que esa lógica quede en un solo lugar.
La ideas es que aca tambien esten los metodos de pregutna y respuesta tambien.
.
"""
from __future__ import annotations
from typing import TYPE_CHECKING



if TYPE_CHECKING:
    from ext.protorouter_lib.managers.arp_request_manager import ArpRequestManager
    from ext.protorouter_lib.managers.arp_table_manager import ArpTableManager
    from ext.protorouter_lib.managers.flow_info_manager import FlowInfoManager
    from ext.protorouter_lib.managers.flow_manager import FlowManager
    from ext.protorouter_lib.managers.nat_table_manager import NatTableManager
    from ext.protorouter_lib.managers.packet_forward_manager import PacketForwardManager
    from ext.protorouter_lib.openflow_sender import OpenFlowSender

from pox.openflow import ethernet, PacketIn

from protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger


class NatManager:
    def __init__(self, flow_info_manager: FlowInfoManager, packet_forward_manager: PacketForwardManager, arp_table_manager: ArpTableManager, nat_table_manager: NatTableManager, arp_request_manager: ArpRequestManager, flow_manager: FlowManager, initial_port: int, of_sender: OpenFlowSender):
        self.cfg = ControllerConfig.get()
        self.of_sender = of_sender
        self._next_port = initial_port
        self._free_ports: list = []  # puertos liberados, listos para reusar
        self._entries: dict = {}  # nat_public_port -> NatEntry
        self.flow_info_manager: FlowInfoManager = flow_info_manager
        self.packet_forward_manager: PacketForwardManager = packet_forward_manager
        self.nat_table_manager: NatTableManager = nat_table_manager
        self.arp_table_manager: ArpTableManager = arp_table_manager
        self.arp_request_manager: ArpRequestManager = arp_request_manager
        self.flow_manager: FlowManager = flow_manager

    def handle_ip(self, event: PacketIn):
        packet: ethernet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
        ip_dst = ip_pkt.dstip

        Logger.info_cyan(
            f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}",
        )

        if not ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            Logger.info_red(
                f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )
            return

        Logger.info_green(
            f"MATCH: {ip_pkt.srcip} belongs to private network {PRIVATE_SUBNET}/{PRIVATE_MASK}",
        )

        arp_entry = self.arp_table_manager.get(ip_dst)
        if arp_entry is None:
            self.arp_request_manager.ask_for_mac_to_public_host(event)
            return
        self.forward_with_known_mac(event, arp_entry)

    def forward_with_known_mac(self, event, arp_entry):
        packet = event.parsed

        flow_info = self.flow_info_manager.extract_flow_info(packet, event.port)
        if flow_info is None:
            return

        nat_entry = self.nat_table_manager.get(flow_info)
        if nat_entry is not None:
            Logger.info_yellow(f"Paquete repetido para un flujo ya en curso (estado={nat_entry.state}), se descarta",)
            return

        nat_entry = self.nat_table_manager.put_and_get(flow_info)

        raw_packet: bytes = event.ofp.data

        self.nat_table_manager.mark_installed(nat_entry, arp_entry.mac, arp_entry.switch_openflow_port)
        self.flow_manager.install_flows(nat_entry)

        Logger.info_green(f"NAT entry completed:\n{nat_entry}")

        self.packet_forward_manager.forward_packet(raw_packet)
