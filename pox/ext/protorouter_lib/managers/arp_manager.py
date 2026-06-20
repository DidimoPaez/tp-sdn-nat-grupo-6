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

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from protorouter_lib.openflow_sender import OpenFlowSender
import pox.openflow.libopenflow_01 as of

from ext.protorouter_lib.utils.logger import Logger
from ext.protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.managers.nat_manager import NatManager
from protorouter_lib.constants import PRIVATE, PUBLIC
from protorouter_lib.models.arp_entry import ArpEntry


class ArpManager:
    def __init__(self, nat_manager: NatManager, private_network: IPAddr, private_mask: int, conn, of_sender: OpenFlowSender):
        self.cfg = ControllerConfig.get()
        self.nat_manager = nat_manager
        self.connection = conn
        self.of_sender = of_sender
        self._private_network = private_network
        self._private_mask = private_mask

        self._table: dict = {}  # IPAddr -> ArpEntry
        self._pending: dict = {}  # IPAddr -> list[PendingPacket]

    def handle_arp(self, event):
        packet = event.parsed
        arp_packet = packet.payload

        match arp_packet.opcode:
            case arp.REQUEST:
                self.handle_packet_arp_request(event)
            case arp.REPLY:
                self.handle_packet_arp_reply(event)

    def handle_packet_arp_request(self, event):
        Logger.info_yellow("Handling an ARP Request")
        packet = event.parsed
        arp_packet = packet.payload
        in_port = event.port
        addr_asked = packet.payload.protodst

        self.learn_arp_entry(in_port, packet.payload.protosrc, packet.payload.hwsrc)

        if addr_asked == self.cfg.nat_private_ip:
            self.of_sender.make_an_arp_reply(
                arp_packet, self.cfg.nat_private_mac, addr_asked, in_port
            )
            return

        elif addr_asked == self.cfg.nat_public_ip:
            self.of_sender.make_an_arp_reply(
                arp_packet, self.cfg.nat_public_mac, addr_asked, in_port
            )
            return

        Logger.info_yellow(
            f"ARP request ignored: {arp_packet.protosrc} asked for {addr_asked}, "
            f"This IP does not belong to Switch NAT",
        )

    def handle_packet_arp_reply(self, event):
        Logger.info_yellow("Handling an ARP Reply")
        packet = event.parsed
        arp_packet = packet.payload

        host_public_ip = arp_packet.protosrc
        host_public_mac = arp_packet.hwsrc
        public_openflow_port = event.port

        self.learn_arp_entry(public_openflow_port, host_public_ip, host_public_mac)

        pending_list = self.pop_pending(host_public_ip)

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

    def complete_and_forward(self, nat_entry, host_public_mac, public_openflow_port, raw_packet):
        self.nat_manager.mark_installed(nat_entry, host_public_mac, public_openflow_port)
        self.install_flows(nat_entry)

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

    # Tabla ARP
    def learn_arp_entry(self, in_port, ip_addr, mac_addr):
        entry, is_new = self.learn(ip_addr, mac_addr, in_port)
        if is_new:
            Logger.info_cyan(f"ARP learned: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} | type={entry.port_type}")
        else:
            Logger.info_cyan(f"ARP already exists: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} ")
    

    def knows(self, ip_addr) -> bool:
        return IPAddr(ip_addr) in self._table

    def lookup(self, ip_addr):
        return self._table.get(IPAddr(ip_addr))

    def learn(self, ip_addr, mac_addr, in_port):
        ip_addr = IPAddr(ip_addr)
        existing = self._table.get(ip_addr)
        if existing is not None:
            return existing, False

        port_type = (
            PRIVATE
            if ip_addr.inNetwork(self._private_network, self._private_mask)
            else PUBLIC
        )
        entry = ArpEntry(EthAddr(mac_addr), in_port, port_type)
        self._table[ip_addr] = entry
        return entry, True

    # Copia de la tabla actual, para debug
    
    def all_entries(self) -> dict:
        return dict(self._table)

    # Paquetes pendientes de resolución ARP
    
    def queue_pending(self, ip_addr, pending_packet) -> bool:
        ip_addr = IPAddr(ip_addr)
        is_first_for_this_ip = ip_addr not in self._pending
        self._pending.setdefault(ip_addr, []).append(pending_packet)
        return is_first_for_this_ip

    def pop_pending(self, ip_addr) -> list:
        return self._pending.pop(IPAddr(ip_addr), [])

    def has_pending(self, ip_addr) -> bool:
        return IPAddr(ip_addr) in self._pending