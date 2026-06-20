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
    from ext.protorouter_lib.managers.arp_manager import ArpManager

from protorouter_lib.models.nat_entry import NatEntry
from protorouter_lib.models.pending_packet import PendingPacket
from protorouter_lib.openflow_sender import OpenFlowSender

from protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger


class NatManager:
    def __init__(self, connection, initial_port: int, of_sender: OpenFlowSender):
        self.cfg = ControllerConfig.get()
        self.connection = connection
        self.of_sender = of_sender
        self._next_port = initial_port
        self._free_ports: list = []  # puertos liberados, listos para reusar
        self._entries: dict = {}  # nat_public_port -> NatEntry
        self.arp_manager: ArpManager | None = None

    def set_arp_manager(self, manager):
        self.arp_manager = manager

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

        nat_entry, is_new = self.get_or_create_outgoing_entry(
            flow_info.protocol,
            flow_info.host_private_ip,
            flow_info.host_private_port,
            flow_info.host_private_mac,
            flow_info.private_openflow_port,
            flow_info.host_public_ip,
            flow_info.host_public_port,
        )

        snapshot = self.debug_snapshot()
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

        nat_entry, is_new = self.get_or_create_outgoing_entry(
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
        self.arp_manager.complete_and_forward(
            nat_entry, arp_entry.mac, arp_entry.switch_openflow_port, raw_packet
        )

    def add_pending_packet(self, target_ip, pending_packet):
        is_first_for_this_ip = self.arp_manager.queue_pending(
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

    def get_or_create_outgoing_entry(
        self,
        protocol,
        host_private_ip,
        host_private_port,
        host_private_mac,
        private_openflow_port,
        host_public_ip,
        host_public_port,
    ):
        self._evict_stale_entries()

        existing = self._find_outgoing(
            protocol, host_private_ip, host_private_port, host_public_ip, host_public_port
        )
        if existing is not None:
            return existing, False

        nat_public_port = self._assign_public_port()
        entry = NatEntry(
            protocol,
            host_private_ip,
            host_private_port,
            host_private_mac,
            private_openflow_port,
            nat_public_port,
            host_public_ip,
            host_public_port,
            None,  # host_public_mac: todavia no se conoce
            None,  # public_openflow_port: todavia no se conoce
        )
        self._entries[nat_public_port] = entry
        return entry, True

    def lookup_by_incoming(self, nat_public_port):
        self._evict_stale_entries()
        return self._entries.get(nat_public_port)

    def mark_installed(self, entry, host_public_mac, public_openflow_port):
        entry.host_public_mac = host_public_mac
        entry.public_openflow_port = public_openflow_port
        entry.state = STATE_INSTALLED
        entry.touch()


    def _find_outgoing(
        self, protocol, host_private_ip, host_private_port, host_public_ip, host_public_port
    ):
        for entry in self._entries.values():
            if (
                entry.protocol == protocol
                and entry.host_private_ip == host_private_ip
                and entry.host_private_port == host_private_port
                and entry.host_public_ip == host_public_ip
                and entry.host_public_port == host_public_port
            ):
                return entry
        return None

    def _evict_stale_entries(self):
        expired_ports = [
            port for port, entry in self._entries.items() if entry.is_stale()
        ]
        for port in expired_ports:
            self._remove_entry(port)

    def _remove_entry(self, nat_public_port):
        self._entries.pop(nat_public_port, None)
        self._release_port(nat_public_port)

    def _assign_public_port(self) -> int:
        if self._free_ports:
            return self._free_ports.pop()
        port = self._next_port
        self._next_port += 1
        return port

    def _release_port(self, port: int):
        self._free_ports.append(port)

    def handle_flow_removed_outgoing(
        self, protocol, host_private_ip, host_private_port, host_public_ip, host_public_port
    ):
        entry = self._find_outgoing(
            protocol, host_private_ip, host_private_port, host_public_ip, host_public_port
        )
        if entry is None:
            return
        if entry.mark_flow_removed("outgoing"):
            self._remove_entry(entry.nat_public_port)

    def handle_flow_removed_incoming(self, nat_public_port):
        entry = self._entries.get(nat_public_port)
        if entry is None:
            return
        if entry.mark_flow_removed("incoming"):
            self._remove_entry(nat_public_port)

    def debug_snapshot(self):
        """Resumen legible de la tabla actual, para debug/CLI."""
        return [
            {
                "nat_public_port": port,
                "private": f"{entry.host_private_ip}:{entry.host_private_port}",
                "public": f"{entry.host_public_ip}:{entry.host_public_port}",
                "state": entry.state,
            }
            for port, entry in self._entries.items()
        ]