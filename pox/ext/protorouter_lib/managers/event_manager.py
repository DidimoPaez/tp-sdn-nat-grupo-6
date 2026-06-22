from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.flow_manager import FlowManager
    from ext.protorouter_lib.managers.packet_manager import PacketManager

from ext.protorouter_lib.models.event import Event
from ext.protorouter_lib.models.event_type import EventType

class EventManager:
    def __init__(self, flow_manager: FlowManager, packet_manager: PacketManager):
        self.flow_manager: FlowManager = flow_manager
        self.packet_manager: PacketManager = packet_manager

    def create_flow_removed_event(self, pox_event):
        return Event(EventType.FlowRemoved, pox_event)

    def create_flow_packet_in_event(self, pox_event):
        return Event(EventType.PacketIn, pox_event)

    def handle(self, event: Event):
        match event.event_type:
            case EventType.FlowRemoved:
                self.flow_manager.handle_flow_removed(event.pox_event)
            case EventType.PacketIn:
                self.packet_manager.handle_packet_in(event.pox_event)
