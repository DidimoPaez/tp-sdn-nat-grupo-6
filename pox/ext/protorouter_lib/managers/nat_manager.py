"""
NatManager

Por ahora sólo se extrajo de ProtoRouter la asignación de puertos
públicos (lo que antes era self.next_nat_public_port / self.assigned_ports),
para que esa lógica quede en un solo lugar.
La ideas es que aca tambien esten los metodos de pregutna y respuesta tambien.
.
"""

from ext.protorouter_lib.managers.flow_manager import FlowManager
from protorouter_lib.openflow_sender import OpenFlowSender

from protorouter_lib.models.pending_packet import PendingPacket
from protorouter_lib.constants import *
from protorouter_lib.managers.nat_table_manager import NatTableManager
from protorouter_lib.managers.arp_table_manager import ArpTableManager
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger


class NatManager:
    def __init__(self, arp_table_manager: ArpTableManager, nat_table_manager: NatTableManager, flow_manager: FlowManager, initial_port: int, of_sender: OpenFlowSender):
        self.cfg = ControllerConfig.get()
        self.of_sender = of_sender
        self._next_port = initial_port
        self._free_ports: list = []  # puertos liberados, listos para reusar
        self._entries: dict = {}  # nat_public_port -> NatEntry
        self.nat_table_manager: NatTableManager = nat_table_manager
        self.arp_table_manager: ArpTableManager = arp_table_manager
        self.flow_manager: FlowManager = flow_manager

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

            if not self.arp_table_manager.contains(ip_dst):
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

        nat_entry, is_new = self.nat_table_manager.get_or_create_outgoing_entry(
            flow_info.protocol,
            flow_info.host_private_ip,
            flow_info.host_private_port,
            flow_info.host_private_mac,
            flow_info.private_openflow_port,
            flow_info.host_public_ip,
            flow_info.host_public_port,
        )

        snapshot = self.nat_table_manager.debug_snapshot()
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

        arp_entry = self.arp_table_manager.get(target_ip)
        if arp_entry is None:
            self.ask_for_mac_to_public_host(event)
            return

        flow_info = self.extract_flow_info(packet, event.port)
        if flow_info is None:
            return

        nat_entry, is_new = self.nat_table_manager.get_or_create_outgoing_entry(
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

        self.nat_table_manager.mark_installed(nat_entry, arp_entry.mac, arp_entry.switch_openflow_port)
        self.flow_manager.install_flows(nat_entry)

        Logger.info_green(f"NAT entry completed:\n{nat_entry}")

        self.of_sender.forward_of_data(
            raw_packet,
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

    def add_pending_packet(self, target_ip, pending_packet):
        is_first_for_this_ip = self.arp_table_manager.queue_pending(
            target_ip, pending_packet
        )

        if is_first_for_this_ip:
            self.of_sender.make_an_arp_request(
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

    def handle_flow_removed_outgoing(
        self, protocol, host_private_ip, host_private_port, host_public_ip, host_public_port
    ):
        entry = self.nat_table_manager._find_outgoing(
            protocol, host_private_ip, host_private_port, host_public_ip, host_public_port
        )
        if entry is None:
            return
        if entry.mark_flow_removed("outgoing"):
            self.nat_table_manager._remove_entry(entry.nat_public_port)

    def handle_flow_removed_incoming(self, nat_public_port):
        self.nat_table_manager.handle_flow_removed_incoming(nat_public_port)
