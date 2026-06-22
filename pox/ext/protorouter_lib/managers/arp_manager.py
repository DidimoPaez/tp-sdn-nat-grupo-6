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
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.arp_reply_manager import ArpReplyManager
    from ext.protorouter_lib.managers.arp_request_reply_manager import ArpRequestReplyManager

from pox.lib.packet.arp import arp
from pox.openflow import ethernet, PacketIn

from ext.protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig


class ArpManager:
    def __init__(self, arp_request_manager: ArpRequestReplyManager, arp_reply_manager: ArpReplyManager):
        self.cfg = ControllerConfig.get()
        self.arp_request_manager: ArpRequestReplyManager = arp_request_manager
        self.arp_reply_manager: ArpReplyManager = arp_reply_manager

    def handle_arp(self, event: PacketIn):
        packet: ethernet = event.parsed
        arp_packet: arp = packet.payload

        match arp_packet.opcode:
            case arp.REQUEST:
                self.arp_request_manager.handle_packet_arp_request(event)
            case arp.REPLY:
                self.arp_reply_manager.handle_packet_arp_reply(event)
