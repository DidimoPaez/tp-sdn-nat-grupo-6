# Import some POX stuff

import time

from pox.core import core  # Main POX object
from pox.lib.addresses import EthAddr, IPAddr  # Address types
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from protorouter_lib.constants import (
    INITIAL_ASSIGNED_PORT,
    PROTO_TCP,
    PROTO_UDP,
    STATE_INSTALLED,
)
from protorouter_lib.managers.arp_manager import ArpManager
from protorouter_lib.managers.nat_manager import NatManager
from protorouter_lib.models.nat_entry import NatEntry
from protorouter_lib.models.pending_packet import PendingPacket
from protorouter_lib.openflow_sender import OpenFlowSender

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")  # Red interna
PRIVATE_MASK = 24  # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")  # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")  # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")  # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1  # Puerto del switch conectado a la red pública

H1_MAC = EthAddr(
    "00:00:00:00:00:01"
)  # MAC del host externo (TODO: resolver mediante ARP)


class ProtoRouter(object):
    def __init__(self, connection):
        self.nat_private_net = PRIVATE_SUBNET
        self.nat_private_mask = PRIVATE_MASK
        self.nat_private_ip = PRIVATE_IP
        self.nat_public_ip = PUBLIC_IP
        self.nat_private_mac = PRIVATE_MAC
        self.nat_public_mac = PUBLIC_MAC
        self.arp_manager = ArpManager(self.nat_private_net, self.nat_private_mask)
        self.nat_manager = NatManager(INITIAL_ASSIGNED_PORT)

        self.openflow_ports: set = set()
        self.global_counter: int = 1 
        self.connection = connection
        connection.addListeners(self)
        self.openflow_sender = OpenFlowSender(connection=self.connection)

    def _handle_PacketIn(self, event):
        log_color(RED, f"_handle_PacketIn has been called {self.global_counter} times")
        self.global_counter += 1

        packet = event.parsed

        if not packet.parsed:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete."
            )
            return

        if packet.type == ethernet.IP_TYPE:
            self.handle_ip(event)

        elif packet.type == ethernet.ARP_TYPE:
            self.handle_arp_type(event)

        else:
            log_color(RED, "Packet ignored: protocol received: {packet.type}.")

    def handle_arp_type(self, event):
        packet = event.parsed
        arp_packet = packet.payload

        if arp_packet.opcode == arp.REQUEST:
            self.handle_packet_arp_request(event)

        elif arp_packet.opcode == arp.REPLY:
            self.handle_packet_arp_reply(event)

    def handle_packet_arp_reply(self, event):
        log_color(YELLOW, "Handling an ARP Reply")
        packet = event.parsed
        arp_packet = packet.payload

        host_public_ip = arp_packet.protosrc
        host_public_mac = arp_packet.hwsrc
        public_openflow_port = event.port

        self.learn_arp_entry(public_openflow_port, host_public_ip, host_public_mac)

        pending_list = self.arp_manager.pop_pending(host_public_ip)

        if not pending_list:
            log_color(YELLOW, f"No pending packets for {host_public_ip}")
            return
        for pending_packet in pending_list:
            nat_entry = pending_packet.nat_entry

            if nat_entry is None:
                log_color(RED, "[ERROR] Pending packet without NAT entry")
                continue

            nat_entry.host_public_mac = host_public_mac
            nat_entry.public_openflow_port = public_openflow_port
            nat_entry.state = STATE_INSTALLED
            nat_entry.last_seen = time.monotonic()

            log_color(GREEN, f"NAT entry completed after ARP Reply:\n{nat_entry}")

            self.forward_pending_packet(pending_packet)

    def forward_pending_packet(self, pending_packet):
        nat_entry = pending_packet.nat_entry

        if nat_entry is None:
            log_color(RED, "[ERROR] NAT Entry does not exist")
            return

        if nat_entry.host_public_mac is None:
            log_color(RED, "[ERROR] Public host MAC is still unknown")
            return
        self.openflow_sender.forward_of_data(
            pending_packet.raw_packet,
            self.nat_public_mac,
            self.nat_public_ip,
            nat_entry.nat_public_port,
            nat_entry.public_openflow_port,
            nat_entry.host_public_mac,
            nat_entry.host_public_ip,
            nat_entry.host_public_port,
            nat_entry.host_private_ip,
            nat_entry.host_private_port,
        )

    def handle_packet_arp_request(self, event):
        log_color(YELLOW, "Handling an ARP Request")
        packet = event.parsed
        arp_packet = packet.payload
        in_port = event.port
        addr_asked = packet.payload.protodst

        self.learn_arp_entry(in_port, packet.payload.protosrc, packet.payload.hwsrc)

        if addr_asked == self.nat_private_ip:
            self.openflow_sender.make_an_arp_reply(
                arp_packet, self.nat_private_mac, addr_asked, in_port
            )
            return

        elif addr_asked == self.nat_public_ip:
            self.openflow_sender.make_an_arp_reply(
                arp_packet, self.nat_public_mac, addr_asked, in_port
            )
            return

        log_color(
            YELLOW,
            f"ARP request ignored: {arp_packet.protosrc} asked for {addr_asked}, "
            f"This IP does not belong to Switch NAT",
        )

    def learn_arp_entry(self, in_port, ip_addr, mac_addr):
        entry, is_new = self.arp_manager.learn(ip_addr, mac_addr, in_port)

        if is_new:
            log_color(
                CYAN,
                f"ARP learned: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} | type={entry.port_type}",
            )
        else:
            log_color(
                CYAN,
                f"ARP already exists: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} ",
            )

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
        ip_dst = ip_pkt.dstip

        log_color(
            YELLOW,
            f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}",
        )

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(
                GREEN,
                f"MATCH: {ip_pkt.srcip} belongs to private network {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

            if not self.arp_manager.knows(ip_dst):
                self.ask_for_mac_to_public_host(event)
                return

            # # Instalar Flujo Saliente
            # fm = of.ofp_flow_mod()
            # fm.idle_timeout = 10

            # # Filtro (Saliente)
            # fm.match.nw_src = ip_pkt.srcip
            # fm.match.dl_type = 0x800  # IPv4
            # fm.match.in_port = in_port

            # # Acción (Saliente)
            # fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            # fm.actions.append(of.ofp_action_dl_addr.set_dst(H1_MAC))
            # fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            # self.connection.send(fm)

            # # Instalar Flujo Entrante (para respuesta)
            # fm_back = of.ofp_flow_mod()
            # fm_back.idle_timeout = 10

            # # Filtro (Entrante)
            # fm_back.match.nw_src = ip_pkt.dstip
            # fm_back.match.nw_dst = ip_pkt.srcip
            # fm_back.match.dl_type = 0x800  # IPv4
            # fm_back.match.in_port = PUBLIC_PORT

            # # Acción (Entrante)
            # fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            # fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            # fm_back.actions.append(of.ofp_action_output(port=in_port))
            # self.connection.send(fm_back)

            # # Reenviar paquete actual con MACs actualizadas (Los posteriores pasan por flujo)
            # packet.src = PUBLIC_MAC
            # packet.dst = H1_MAC
            # msg = of.ofp_packet_out()
            # msg.data = packet.pack()
            # msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            # log_color(
            #     CYAN,
            #     f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {PUBLIC_MAC} → {H1_MAC} | Out Port: {PUBLIC_PORT}",
            # )
            # self.connection.send(msg)

        else:
            log_color(
                RED,
                f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}",
            )

    def ask_for_mac_to_public_host(self, event):
        packet = event.parsed
        ip_packet = packet.payload
        target_ip = ip_packet.dstip
        if IPAddr(target_ip).inNetwork(self.nat_private_net, self.nat_private_mask):
            log_color(RED, "[ERROR] MAC address Searchs just for private hosts")
            return

        nat_entry = self.make_a_nat_entry(packet, event.port)

        if nat_entry is None:
            return

        raw_packet: bytes = event.ofp.data
        pending_packet = PendingPacket(event.port, raw_packet, nat_entry)

        self.add_pending_packet(target_ip, pending_packet)

    def add_pending_packet(self, target_ip, pending_packet):
        is_first_for_this_ip = self.arp_manager.queue_pending(
            target_ip, pending_packet
        )

        if is_first_for_this_ip:
            self.openflow_sender.make_an_arp_request(
                target_ip, PUBLIC_PORT, self.nat_public_mac, self.nat_public_ip
            )

    def make_a_nat_entry(self, eth_packet, in_port):
        ip_packet = eth_packet.payload
        tcp_packet = eth_packet.find(PROTO_TCP)
        udp_packet = eth_packet.find(PROTO_UDP)

        if udp_packet is not None:
            protocol = PROTO_UDP
            transport_packet = eth_packet.find(PROTO_UDP)
        elif tcp_packet is not None:
            protocol = PROTO_TCP
            transport_packet = eth_packet.find(PROTO_TCP)
        else:
            return None

        host_private_ip = ip_packet.srcip
        host_public_ip = ip_packet.dstip

        if not IPAddr(host_private_ip).inNetwork(
            self.nat_private_net, self.nat_private_mask
        ):
            return None

        host_private_port = transport_packet.srcport
        host_public_port = transport_packet.dstport
        host_private_mac = eth_packet.src
        private_openflow_port = in_port
        host_public_mac = None
        public_openflow_port = PUBLIC_PORT

        nat_public_port = self.nat_manager.assign_public_port()

        nat_entry = NatEntry(
            protocol,
            host_private_ip,
            host_private_port,
            host_private_mac,
            private_openflow_port,
            nat_public_port,
            host_public_ip,
            host_public_port,
            host_public_mac,
            public_openflow_port,
        )
        log_color(YELLOW, f"New NAT Entry in pending_packets:\n {nat_entry}\n")

        return nat_entry


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)