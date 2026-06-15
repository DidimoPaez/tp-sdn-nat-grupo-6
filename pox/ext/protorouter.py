# Import some POX stuff


import time

import pox.openflow.libopenflow_01 as of  # OpenFlow 1.0 library
from pox.core import core  # Main POX object
from pox.lib.addresses import EthAddr, IPAddr  # Address types
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

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

PRIVATE: str = "private"
PUBLIC: str = "public"

MAC_ETHER_LENGTH: int = 6  # MAC addr Ethernet mide 48 bits
IP_ADDR_LENGTH: int = 4  ##dirección IPv4 mide 32 bits
MAC_UNKNOWN: str = "00:00:00:00:00:00"
ETHER_BROADCAST: str = "ff:ff:ff:ff:ff:ff"

TIME_OUT: int = 60
STATE_PENDING_ARP = "Pending ARP"
STATE_INSTALLED = "Installed"

INITIAL_ASSIGNED_PORT: int = 10000


class ArpEntry:
    def __init__(self, mac: str, switch_openflow_port: int, port_type: str):
        self.mac = mac
        self.switch_openflow_port = switch_openflow_port
        self.port_type = port_type


class PendingPacket:
    def __init__(self, in_port: int, raw_packet: bytes, nat_entry):
        self.in_port = in_port
        self.raw_packet = raw_packet
        self.nat_entry = nat_entry


class ProtoRouter(object):
    def __init__(self, connection):
        self.nat_private_net = PRIVATE_SUBNET
        self.nat_private_mask = PRIVATE_MASK
        self.nat_private_ip = PRIVATE_IP
        self.nat_public_ip = PUBLIC_IP
        self.nat_private_mac = PRIVATE_MAC
        self.nat_public_mac = PUBLIC_MAC
        self.next_nat_public_port = INITIAL_ASSIGNED_PORT
        self.assigned_ports = set()
        self.pending_packets: dict = {}
        self.openflow_ports: set = set()
        self.arp_table: dict = {}
        self.global_counter: int = 1  ##
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        log_color(
            RED,
            f" - CANTIDAD DE VECES QUE SE HA ENTRADO A _handle_PacketIn: [{self.global_counter}] - ",
        )  ##
        self.global_counter += 1
        packet = event.parsed

        if not packet.parsed:
            log.warning(
                "[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete."
            )
            return

        if packet.type == ethernet.IP_TYPE:
            self.handle_ip(event)
            log_color(
                YELLOW,
                f"ALGUNAS VARIABLES:\n\
                        event.port: {event.port}\n\
                        packet.find(udp): {packet.find('udp')}\n\
                        packet.find(tcp): {packet.find('tcp')}\n",
            )
        elif packet.type == ethernet.ARP_TYPE:
            if packet.payload.opcode == arp.REQUEST:
                self.handle_packet_arp_request(event)
                log_color(
                    YELLOW,
                    f"-SE TIENE UN PACKET IN DE TIPO: arp.REQUEST {arp.REQUEST}-",
                )
                log_color(
                    YELLOW,
                    f"ALGUNAS VARIABLES:\n\
                        event.port: {event.port}\n\
                        packet.find(udp): {packet.find('udp')}\n\
                        packet.find(tcp): {packet.find('tcp')}\n\
                        packet.src: {packet.src}\n\
                        packet.payload.protosrc: {packet.payload.protosrc}\n\
                        packet.payload.protodst: {packet.payload.protodst}\n\
                        packet.payload.hwsrc: {packet.payload.hwsrc}\n\
                        packet.payload.protolen: {packet.payload.protolen}\n\
                        packet.payload.hwlen: {packet.payload.hwlen}\n\
                            ",
                )

            elif packet.payload.opcode == arp.REPLY:
                log_color(
                    YELLOW,
                    f"-SE TIENE UN PACKET IN DE TIPO: arp.REPLY {arp.REPLY}-",
                )
                self.handle_packet_arp_reply(event)
        else:
            log_color(YELLOW, "Packet ignored: protocol received: {packet.type}.")

    def handle_packet_arp_reply(self, event):
        packet = event.parsed
        log_color(
            YELLOW,
            f"ALGUNAS VARIABLES EN - handle_packet_arp_reply -:\n\
                        event.port: {event.port}\n\
                        packet.find(udp): {packet.find('udp')}\n\
                        packet.find(tcp): {packet.find('tcp')}\n\
                        packet.src: {packet.src}\n\
                        packet.payload.protosrc: {packet.payload.protosrc}\n\
                        packet.payload.protodst: {packet.payload.protodst}\n\
                        packet.payload.hwsrc: {packet.payload.hwsrc}\n\
                        packet.payload.hwdst: {packet.payload.hwdst}\n\
                        packet.payload.protolen: {packet.payload.protolen}\n\
                        packet.payload.hwlen: {packet.payload.hwlen}\n\
                            ",
        )

    def handle_packet_arp_request(self, event):
        packet = event.parsed
        arp_packet = packet.payload
        in_port = event.port
        addr_asked = packet.payload.protodst

        self.learn_arp_entry(in_port, packet.payload.protosrc, packet.payload.hwsrc)

        if addr_asked == self.nat_private_ip:
            self.make_an_arp_reply(
                arp_packet, self.nat_private_mac, addr_asked, in_port
            )
            return

        elif addr_asked == self.nat_public_ip:
            self.make_an_arp_reply(arp_packet, self.nat_public_mac, addr_asked, in_port)
            return

        log_color(
            YELLOW,
            f"ARP request ignored: {arp_packet.protosrc} asked for {addr_asked}, "
            f"This IP does not belong to Switch NAT",
        )

    def learn_arp_entry(self, in_port, ip_addr, mac_addr):
        if self.arp_table.get(ip_addr):
            log_color(
                CYAN,
                f"ARP already exists: {IPAddr(ip_addr)} -> {EthAddr(mac_addr)} | port={in_port} ",
            )
            return

        if IPAddr(ip_addr).inNetwork(self.nat_private_net, self.nat_private_mask):
            port_type = PRIVATE
        else:
            port_type = PUBLIC

        self.arp_table[IPAddr(ip_addr)] = ArpEntry(
            EthAddr(mac_addr), in_port, port_type
        )

        log_color(
            CYAN,
            f"ARP learned: {IPAddr(ip_addr)} -> {EthAddr(mac_addr)} | port={in_port} | type={port_type}",
        )

    def make_an_arp_reply(self, arp_packet, mac_response, addr_response, outport):
        reply = arp()
        reply.hwtype = arp_packet.hwtype
        reply.prototype = arp_packet.prototype
        reply.hwlen = arp_packet.hwlen
        reply.protolen = arp_packet.protolen
        reply.opcode = arp.REPLY

        reply.hwsrc = EthAddr(mac_response)
        reply.hwdst = arp_packet.hwsrc
        reply.protosrc = IPAddr(addr_response)
        reply.protodst = arp_packet.protosrc

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = arp_packet.hwsrc
        ether.src = mac_response
        ether.payload = reply

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=outport))
        log_color(
            RED,
            f"Responding MAC: {reply.hwsrc} | From IP: {reply.protosrc} | To MAC: {reply.hwdst} | To IP: {reply.protodst}",
        )
        self.connection.send(msg)

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

            if ip_dst not in self.arp_table:
                self.ask_for_mac_to_public_host(event)
                return

            # Instalar Flujo Saliente
            fm = of.ofp_flow_mod()
            fm.idle_timeout = 10

            # Filtro (Saliente)
            fm.match.nw_src = ip_pkt.srcip
            fm.match.dl_type = 0x800  # IPv4
            fm.match.in_port = in_port

            # Acción (Saliente)
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(H1_MAC))
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(fm)

            # Instalar Flujo Entrante (para respuesta)
            fm_back = of.ofp_flow_mod()
            fm_back.idle_timeout = 10

            # Filtro (Entrante)
            fm_back.match.nw_src = ip_pkt.dstip
            fm_back.match.nw_dst = ip_pkt.srcip
            fm_back.match.dl_type = 0x800  # IPv4
            fm_back.match.in_port = PUBLIC_PORT

            # Acción (Entrante)
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(fm_back)

            # Reenviar paquete actual con MACs actualizadas (Los posteriores pasan por flujo)
            packet.src = PUBLIC_MAC
            packet.dst = H1_MAC
            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            log_color(
                CYAN,
                f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {PUBLIC_MAC} → {H1_MAC} | Out Port: {PUBLIC_PORT}",
            )
            self.connection.send(msg)

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
        raw_packet: bytes = event.ofp.data

        nat_entry = self.make_a_nat_entry(packet, event.port)

        pending_packet = PendingPacket(PUBLIC_PORT, raw_packet, nat_entry)

        if target_ip not in self.pending_packets:
            self.pending_packets[target_ip] = []
            self.make_an_arp_request(target_ip, PUBLIC_PORT)

        self.pending_packets[target_ip].append(pending_packet)

    def make_a_nat_entry(self, eth_packet, in_port):
        ip_packet = eth_packet.payload
        tcp_packet = eth_packet.find("tcp")
        udp_packet = eth_packet.find("udp")

        if udp_packet is not None:
            protocol = "udp"
            transport_packet = eth_packet.find("udp")
        elif tcp_packet is not None:
            protocol = "tcp"
            transport_packet = eth_packet.find("tcp")
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

        new_nat_public_port = self.next_nat_public_port
        self.assigned_ports.add(new_nat_public_port)
        self.next_nat_public_port += 1

        nat_public_port = new_nat_public_port

        nat_entry = self.NatEntry(
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

    class NatEntry:
        def __init__(
            self,
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
        ):

            self.protocol: str = protocol

            self.host_private_ip: str = host_private_ip
            self.host_private_port: int = host_private_port
            self.host_private_mac: str = host_private_mac
            self.private_openflow_port: int = private_openflow_port

            self.nat_public_port: int = nat_public_port

            self.host_public_ip: str = host_public_ip
            self.host_public_port: int = host_public_port
            self.host_public_mac = host_public_mac
            self.public_openflow_port = public_openflow_port

            self.last_seen = time.monotonic()
            self.idle_timeout: int = TIME_OUT
            self.state: str = STATE_PENDING_ARP

        def __repr__(self):
            return (
                "NatEntry("
                f"protocol={self.protocol}, \n"
                f"private={self.host_private_ip}:{self.host_private_port}, \n"
                f"private_mac={self.host_private_mac}, \n"
                f"private_of_port={self.private_openflow_port}, \n"
                f"nat_public_port={self.nat_public_port}, \n"
                f"public={self.host_public_ip}:{self.host_public_port}, \n"
                f"public_mac={self.host_public_mac}, \n"
                f"public_of_port={self.public_openflow_port}, \n"
                f"state={self.state} \n"
                ")"
            )

    def make_an_arp_request(self, target_ip, outport):
        target_ip = IPAddr(target_ip)

        request = arp()
        request.hwtype = arp.HW_TYPE_ETHERNET
        request.prototype = arp.PROTO_TYPE_IP
        request.hwlen = MAC_ETHER_LENGTH
        request.protolen = IP_ADDR_LENGTH
        request.opcode = arp.REQUEST

        request.hwsrc = self.nat_public_mac
        request.hwdst = EthAddr(MAC_UNKNOWN)
        request.protosrc = self.nat_public_ip
        request.protodst = target_ip

        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = EthAddr(ETHER_BROADCAST)
        ether.src = self.nat_public_mac
        ether.payload = request

        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port=outport))
        log_color(
            RED,
            f"Requesting MAC | From IP: {request.protosrc} | From MAC: {request.hwsrc} | To IP: {request.protodst}",
        )
        self.connection.send(msg)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
