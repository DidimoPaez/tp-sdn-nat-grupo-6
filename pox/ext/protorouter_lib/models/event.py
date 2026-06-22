
from ext.protorouter_lib.models.event_type import EventType
from pox.pox.openflow import FlowRemoved, PacketIn


class Event:
    def __init__(self, event_type: EventType, pox_event: FlowRemoved | PacketIn):
        self.event_type: EventType = event_type
        self.pox_event: FlowRemoved | PacketIn = pox_event
