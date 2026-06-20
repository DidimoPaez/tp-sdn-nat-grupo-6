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
        self.arp_manager = ArpManager(self.cfg.nat_private_net, self.cfg.nat_private_mask)
        self.nat_manager = NatManager(INITIAL_ASSIGNED_PORT)

        self.openflow_ports: set = set()
        self.global_counter: int = 1 
        self.connection = connection
        connection.addListeners(self)
        self.openflow_sender = OpenFlowSender(connection=self.connection)

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
        packet = event.parsed
        arp_packet = packet.payload

        if arp_packet.opcode == arp.REQUEST:
            self.handle_packet_arp_request(event)

        elif arp_packet.opcode == arp.REPLY:
            self.handle_packet_arp_reply(event)

    def handle_packet_arp_reply(self, event):
        Logger.info_yellow("Handling an ARP Reply")
        packet = event.parsed
        arp_packet = packet.payload

        host_public_ip = arp_packet.protosrc
        host_public_mac = arp_packet.hwsrc
        public_openflow_port = event.port

        self.learn_arp_entry(public_openflow_port, host_public_ip, host_public_mac)

        pending_list = self.arp_manager.pop_pending(host_public_ip)

        if not pending_list:
            Logger.info_yellow(f"No pending packets for {host_public_ip}")
            return

        for pending_packet in pending_list:
            nat_entry = pending_packet.nat_entry

            if nat_entry is None:
                Logger.info_red("[ERROR] Pending packet without NAT entry")
                continue

            self.complete_and_forward(
                nat_entry, host_public_mac, public_openflow_port, pending_packet.raw_packet
            )

    def handle_packet_arp_request(self, event):
        Logger.info_yellow("Handling an ARP Request")
        packet = event.parsed
        arp_packet = packet.payload
        in_port = event.port
        addr_asked = packet.payload.protodst

        self.learn_arp_entry(in_port, packet.payload.protosrc, packet.payload.hwsrc)

        if addr_asked == self.cfg.nat_private_ip:
            self.openflow_sender.make_an_arp_reply(
                arp_packet, self.cfg.nat_private_mac, addr_asked, in_port
            )
            return

        elif addr_asked == self.cfg.nat_public_ip:
            self.openflow_sender.make_an_arp_reply(
                arp_packet, self.cfg.nat_public_mac, addr_asked, in_port
            )
            return

        Logger.info_yellow(
            f"ARP request ignored: {arp_packet.protosrc} asked for {addr_asked}, "
            f"This IP does not belong to Switch NAT",
        )

    def learn_arp_entry(self, in_port, ip_addr, mac_addr):
        entry, is_new = self.arp_manager.learn(ip_addr, mac_addr, in_port)

        if is_new:
            Logger.info_cyan(f"ARP learned: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} | type={entry.port_type}")
        else:
            Logger.info_cyan(f"ARP already exists: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} ")

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

    """
        Instala en el switch las dos reglas (saliente y entrante) para
        esta NatEntry ya resuelta. Es la versión PAT del bloque base de
        instalación de flujos: misma estrategia (dos flow_mod), pero con
        match por 5-tupla y acciones de NAT en vez de un solo par de MACs
        fijo.
        codigo original de hugo :
        """
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

    def install_flows(self, nat_entry):
        ip_proto = PROTO_IP_NUMBER.get(nat_entry.protocol)
        if ip_proto is None:
            Logger.info_red(f"[ERROR] Protocolo desconocido para instalar flujo: {nat_entry.protocol}",)
            return

        # Instalar Flujo Saliente
        fm = of.ofp_flow_mod()
        fm.idle_timeout = nat_entry.idle_timeout
        fm.flags = of.OFPFF_SEND_FLOW_REM

        # Filtro (Saliente)
        fm.match.dl_type = 0x800  # IPv4
        fm.match.in_port = nat_entry.private_openflow_port
        fm.match.nw_proto = ip_proto
        fm.match.nw_src = nat_entry.host_private_ip
        fm.match.nw_dst = nat_entry.host_public_ip
        fm.match.tp_src = nat_entry.host_private_port
        fm.match.tp_dst = nat_entry.host_public_port

        # Acción (Saliente)
        fm.actions.append(of.ofp_action_dl_addr.set_src(self.cfg.nat_public_mac))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(nat_entry.host_public_mac))
        fm.actions.append(of.ofp_action_nw_addr.set_src(self.cfg.nat_public_ip))
        fm.actions.append(of.ofp_action_tp_port.set_src(nat_entry.nat_public_port))
        fm.actions.append(of.ofp_action_output(port=nat_entry.public_openflow_port))
        self.connection.send(fm)

        # Instalar Flujo Entrante (para respuesta)
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = nat_entry.idle_timeout
        fm_back.flags = of.OFPFF_SEND_FLOW_REM

        # Filtro (Entrante)
        fm_back.match.dl_type = 0x800  # IPv4
        fm_back.match.in_port = nat_entry.public_openflow_port
        fm_back.match.nw_proto = ip_proto
        fm_back.match.nw_src = nat_entry.host_public_ip
        fm_back.match.nw_dst = self.cfg.nat_public_ip
        fm_back.match.tp_src = nat_entry.host_public_port
        fm_back.match.tp_dst = nat_entry.nat_public_port

        # Acción (Entrante)
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(self.cfg.nat_private_mac))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(nat_entry.host_private_mac))
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(nat_entry.host_private_ip))
        fm_back.actions.append(of.ofp_action_tp_port.set_dst(nat_entry.host_private_port))
        fm_back.actions.append(of.ofp_action_output(port=nat_entry.private_openflow_port))
        self.connection.send(fm_back)

        Logger.info_green(
            f"Flujos instalados para puerto público {nat_entry.nat_public_port}"
        )

    """
        Termina de resolver una NatEntry (ya con MAC pública conocida),
        instala sus flujos y reenvía el paquete que la disparó — el
        equivalente al "Reenviar paquete actual" del bloque base, pero
        usando openflow_sender.forward_of_data (que ya traduce IP/puerto,
        no solo MAC)
    """
    def complete_and_forward(self, nat_entry, host_public_mac, public_openflow_port, raw_packet):
        self.nat_manager.mark_installed(nat_entry, host_public_mac, public_openflow_port)
        self.install_flows(nat_entry)

        Logger.info_green(f"NAT entry completed:\n{nat_entry}")

        self.openflow_sender.forward_of_data(
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