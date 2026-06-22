"""
ArpManager

Encapsula todo lo relacionado a ARP que antes estaba sueltо en ProtoRouter:

  - self.arp_table       -> tabla IP -> ArpEntry
  - self.pending_packets -> paquetes que están esperando que se resuelva
                             una MAC vía ARP

La idea es que ProtoRouter  no manipule estos diccionarios directamente.
Le "pregunta" al manager (knows, lookup, learn, queue_pending,
pop_pending) y el manager responde con la información o con un resultado
simple (True/False, una entrada, una lista). 
"""

from ext.protorouter_lib.managers.nat_table_manager import NatTableManager
from pox.lib.packet.arp import arp
from pox.openflow import ethernet, PacketIn

from protorouter_lib.openflow_sender import OpenFlowSender
from ext.protorouter_lib.utils.logger import Logger
from ext.protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.managers.arp_table_manager import ArpTableManager
from ext.protorouter_lib.managers.flow_manager import FlowManager


class ArpManager:
    def __init__(self, arp_table_manager: ArpTableManager, nat_table_manager: NatTableManager, flow_manager: FlowManager, of_sender: OpenFlowSender):
        self.cfg = ControllerConfig.get()
        self.flow_manager: FlowManager = flow_manager
        self.of_sender = of_sender
        self.arp_table_manager: ArpTableManager = arp_table_manager
        self.nat_table_manager: NatTableManager = nat_table_manager

    def handle_arp(self, event: PacketIn):
        packet: ethernet = event.parsed
        arp_packet: arp = packet.payload

        match arp_packet.opcode:
            case arp.REQUEST:
                self.handle_packet_arp_request(event)
            case arp.REPLY:
                self.handle_packet_arp_reply(event)

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

        mac_response = self.get_mac_for_given_ip(addr_asked)
        self.arp_table_manager.learn_arp_entry(in_port, packet.payload.protosrc, packet.payload.hwsrc)

        if mac_response is None:
            Logger.info_yellow(
                f"ARP request ignored: {arp_packet.protosrc} asked for {addr_asked}, "
                f"This IP does not belong to Switch NAT",
            )
            return

        self.of_sender.make_an_arp_reply(arp_packet, mac_response, addr_asked, in_port)

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

        self.forward_pending_packets(pending_list, host_public_mac, openflow_public_port)

    def forward_pending_packets(self, pending_packets, host_public_mac, openflow_public_port):
        for pending_packet in pending_packets:
            nat_entry = pending_packet.nat_entry

            if nat_entry is None:
                Logger.info_red("[ERROR] Pending packet without NAT entry")
                continue

            self.nat_table_manager.mark_installed(nat_entry, host_public_mac, openflow_public_port)
            self.flow_manager.install_flows(nat_entry)

            Logger.info_green(f"NAT entry completed:\n{nat_entry}")

            self.forward_packet_to_sender(pending_packet)

    def forward_packet_to_sender(self, packet):
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
