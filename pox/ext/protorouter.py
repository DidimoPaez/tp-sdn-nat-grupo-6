from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from protorouter_lib.constants import *
import pox.openflow.libopenflow_01 as of
from protorouter_lib.managers.arp_manager import ArpManager
from protorouter_lib.managers.nat_manager import NatManager
from protorouter_lib.models.pending_packet import PendingPacket
from protorouter_lib.openflow_sender import OpenFlowSender
from collections import namedtuple

from ext.protorouter_lib.utils.logger import Logger
from ext.protorouter_lib.managers.controller_config import ControllerConfig

# Datos de un flujo saliente, parseados una sola vez del paquete IP.
FlowInfo = namedtuple(
    "FlowInfo",
    [
        "protocol",
        "host_private_ip",
        "host_private_port",
        "host_private_mac",
        "private_openflow_port",
        "host_public_ip",
        "host_public_port",
    ],
)

class ProtoRouter(object):
    def __init__(self, connection):
        self.cfg = ControllerConfig.get()
        self.openflow_sender = OpenFlowSender(connection=self.connection)
        self.nat_manager = NatManager(INITIAL_ASSIGNED_PORT)
        self.arp_manager = ArpManager(self.nat_manager, self.cfg.nat_private_net, self.cfg.nat_private_mask, connection, self.openflow_sender)

        self.openflow_ports: set = set()
        self.global_counter: int = 1 
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        Logger.info_red(f"_handle_PacketIn has been called {self.global_counter} times")
        self.global_counter += 1

        packet = event.parsed

        if not packet.parsed:
            Logger.warn("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if packet.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        elif packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        else:
            Logger.info_red("Packet ignored: protocol received: {packet.type}.")

    def handle_arp(self, event):
        self.arp_manager.handle_arp(event)

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
        ip_dst = ip_pkt.dstip

        Logger.info_cyan(
            f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}",
        )

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            Logger.info_green(
                f"MATCH: {ip_pkt.srcip} belongs to private network {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

            if not self.arp_manager.knows(ip_dst):
                self.ask_for_mac_to_public_host(event)
                return

            self.forward_with_known_mac(event)

        else:
            Logger.info_red(
                f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

    def ask_for_mac_to_public_host(self, event):
        packet = event.parsed
        ip_packet = packet.payload
        target_ip = ip_packet.dstip
        if IPAddr(target_ip).inNetwork(self.cfg.nat_private_net, self.cfg.nat_private_mask):
            Logger.info_red("[ERROR] MAC address Searchs just for private hosts")
            return

        flow_info = self.extract_flow_info(packet, event.port)
        if flow_info is None:
            return

        nat_entry, is_new = self.nat_manager.get_or_create_outgoing_entry(
            flow_info.protocol,
            flow_info.host_private_ip,
            flow_info.host_private_port,
            flow_info.host_private_mac,
            flow_info.private_openflow_port,
            flow_info.host_public_ip,
            flow_info.host_public_port,
        )

        snapshot = self.nat_manager.debug_snapshot()
        Logger.info_cyan(f"Tabla NAT ({len(snapshot)} entrada/s): {snapshot}")

        if not is_new:
            Logger.info_yellow(f"Paquete repetido para un flujo ya en curso (estado={nat_entry.state}), se descarta",)
            return

        Logger.info_yellow(f"New NAT Entry (PENDING):\n {nat_entry}\n")

        raw_packet: bytes = event.ofp.data
        pending_packet = PendingPacket(event.port, raw_packet, nat_entry)

        self.add_pending_packet(target_ip, pending_packet)

    def forward_with_known_mac(self, event):
        packet = event.parsed
        ip_packet = packet.payload
        target_ip = ip_packet.dstip

        arp_entry = self.arp_manager.lookup(target_ip)
        if arp_entry is None:
            self.ask_for_mac_to_public_host(event)
            return

        flow_info = self.extract_flow_info(packet, event.port)
        if flow_info is None:
            return

        nat_entry, is_new = self.nat_manager.get_or_create_outgoing_entry(
            flow_info.protocol,
            flow_info.host_private_ip,
            flow_info.host_private_port,
            flow_info.host_private_mac,
            flow_info.private_openflow_port,
            flow_info.host_public_ip,
            flow_info.host_public_port,
        )

        if not is_new:
            Logger.info_yellow(
                f"Paquete con MAC ya conocida pero flujo ya en curso (estado={nat_entry.state}), se descarta",
            )
            return

        raw_packet: bytes = event.ofp.data
        self.complete_and_forward(
            nat_entry, arp_entry.mac, arp_entry.switch_openflow_port, raw_packet
        )

    def add_pending_packet(self, target_ip, pending_packet):
        is_first_for_this_ip = self.arp_manager.queue_pending(
            target_ip, pending_packet
        )

        if is_first_for_this_ip:
            self.openflow_sender.make_an_arp_request(
                target_ip, PUBLIC_PORT, self.cfg.nat_public_mac, self.cfg.nat_public_ip
            )

    def extract_flow_info(self, eth_packet, in_port):
        ip_packet = eth_packet.payload
        udp_packet = eth_packet.find(PROTO_UDP)
        tcp_packet = eth_packet.find(PROTO_TCP)

        if udp_packet is not None:
            protocol = PROTO_UDP
            transport_packet = udp_packet
        elif tcp_packet is not None:
            protocol = PROTO_TCP
            transport_packet = tcp_packet
        else:
            return None

        host_private_ip = ip_packet.srcip
        if not IPAddr(host_private_ip).inNetwork(
            self.cfg.nat_private_net, self.cfg.nat_private_mask
        ):
            return None

        return FlowInfo(
            protocol=protocol,
            host_private_ip=host_private_ip,
            host_private_port=transport_packet.srcport,
            host_private_mac=eth_packet.src,
            private_openflow_port=in_port,
            host_public_ip=ip_packet.dstip,
            host_public_port=transport_packet.dstport,
        )
    
    def _handle_FlowRemoved(self, event):
        match = event.ofp.match

        if match.nw_dst == self.cfg.nat_public_ip:
            nat_public_port = match.tp_dst
            self.nat_manager.handle_flow_removed_incoming(nat_public_port)
            Logger.info_yellow(
                f"Flujo entrante removido por el switch (puerto público {nat_public_port})"
            )
        else:
            protocol = IP_NUMBER_TO_PROTO.get(match.nw_proto)
            if protocol is None:
                return
            self.nat_manager.handle_flow_removed_outgoing(
                protocol, match.nw_src, match.tp_src, match.nw_dst, match.tp_dst
            )
            Logger.info_yellow(f"Flujo saliente removido por el switch ({match.nw_src}:{match.tp_src} -> {match.nw_dst}:{match.tp_dst})")

def launch():
    def start_switch(event):
        Logger.info_yellow(f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)