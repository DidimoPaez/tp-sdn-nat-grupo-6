from pox.core import core
from ext.protorouter_lib.managers.arp_reply_manager import ArpReplyManager
from ext.protorouter_lib.managers.arp_request_reply_manager import ArpRequestReplyManager
from ext.protorouter_lib.managers.event_manager import EventManager
from ext.protorouter_lib.managers.packet_forward_manager import PacketForwardManager
from ext.protorouter_lib.managers.packet_manager import PacketManager
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

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
        self.openflow_sender = OpenFlowSender(self.connection)

        self.arp_table_manager = ArpTableManager(self.cfg.nat_private_net, self.cfg.nat_private_mask)
        self.nat_table_manager = NatTableManager(INITIAL_ASSIGNED_PORT, self.arp_table_manager)
        
        self.nat_manager = NatManager(self.arp_table_manager, self.nat_table_manager, self.flow_manager, INITIAL_ASSIGNED_PORT, self.openflow_sender)

        self.flow_manager = FlowManager(self.connection, self.nat_manager)
        self.packet_manager = PacketManager(self.arp_manager, self.nat_manager)
        self.packet_forward_manager = PacketForwardManager(self.openflow_sender)
        self.arp_request_manager = ArpRequestReplyManager(self.arp_table_manager, self.openflow_sender)
        self.arp_reply_manager = ArpReplyManager(self.arp_table_manager, self.nat_table_manager, self.packet_forward_manager, self.flow_manager)
        self.arp_manager = ArpManager(self.arp_request_manager, self.arp_reply_manager)

        self.event_manager = EventManager(self.flow_manager, self.packet_manager)

        self.openflow_ports: set = set()
        self.global_counter: int = 1 
        connection.addListeners(self)

    def _handle_ConnectionUp(self, event):
        dpid = event.dpid
        connection = event.connection

        Logger.info_cyan("=== CONNECTION UP ===")
        Logger.info_cyan(f"Switch DPID: {dpidToStr(dpid)}")
        Logger.info_cyan(f"Remote: {connection}")

        try:
            msg = of.ofp_barrier_request()
            connection.send(msg)
            Logger.info_cyan("Barrier request enviado OK")
        except Exception as e:
            Logger.error(f"Error enviando barrier: {e}")

        try:
            fm = of.ofp_flow_mod()
            fm.priority = 0
            fm.match = of.ofp_match()  # match vacío = todo
            fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            connection.send(fm)
            Logger.info_cyan("Flow default instalado (table-miss -> controller)")
        except Exception as e:
            Logger.error(f"Error instalando flow default: {e}")

        Logger.info_cyan("=== END CONNECTION UP ===")

    def _handle_PacketIn(self, event):
        self.event_manager.handle(
            self.event_manager.create_flow_packet_in_event(event)
        )
    
    def _handle_FlowRemoved(self, event):
        self.event_manager.handle(
            self.event_manager.create_flow_removed_event(event)
        )

def launch():
    def start_switch(event):
        Logger.info_yellow(f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)