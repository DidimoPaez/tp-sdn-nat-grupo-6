from pox.core import core
from pox.lib.packet.ethernet import ethernet
from protorouter_lib.constants import *
from protorouter_lib.managers.arp_manager import ArpManager
from protorouter_lib.managers.nat_manager import NatManager
from protorouter_lib.openflow_sender import OpenFlowSender

from ext.protorouter_lib.managers.nat_table_manager import NatTableManager
from ext.protorouter_lib.managers.arp_table_manager import ArpTableManager
from ext.protorouter_lib.managers.flow_manager import FlowManager
from ext.protorouter_lib.utils.logger import Logger
from ext.protorouter_lib.managers.controller_config import ControllerConfig

class ProtoRouter(object):
    def __init__(self, connection):
        self.cfg = ControllerConfig.get()
        self.connection = connection
        self.openflow_sender = OpenFlowSender(connection=self.connection)
        self.arp_table_manager = ArpTableManager(self.cfg.nat_private_net, self.cfg.nat_private_mask)
        self.nat_table_manager = NatTableManager(INITIAL_ASSIGNED_PORT, self.arp_table_manager)
        self.flow_manager = FlowManager(self.connection)
        self.nat_manager = NatManager(self.arp_table_manager, self.nat_table_manager, self.flow_manager, INITIAL_ASSIGNED_PORT, self.openflow_sender)
        self.arp_manager = ArpManager(self.arp_table_manager, self.nat_table_manager, self.flow_manager, self.openflow_sender)

        self.openflow_ports: set = set()
        self.global_counter: int = 1 
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        Logger.info_red(f"_handle_PacketIn has been called {self.global_counter} times")
        self.global_counter += 1

        packet = event.parsed

        if not packet.parsed:
            Logger.warn("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if packet.type == ethernet.IP_TYPE:
            self.nat_manager.handle_ip(event)
        elif packet.type == ethernet.ARP_TYPE:
            self.arp_manager.handle_arp(event)
        else:
            Logger.info_red("Packet ignored: protocol received: {packet.type}.")
    
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