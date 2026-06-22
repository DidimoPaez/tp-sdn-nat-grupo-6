from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ext.protorouter_lib.models.flow import Flow

class Flow:
    def __init__(self, protocol, source_mac, source_ip, source_port, destination_ip, destination_port, in_port):
        self.protocol = protocol
        self.source_mac = source_mac
        self.source_ip = source_ip
        self.source_port = source_port
        self.in_port = in_port

        self.destination_ip = destination_ip
        self.destination_port = destination_port

    def __iter__(self):
        yield self.protocol
        yield self.source_mac
        yield self.source_ip
        yield self.source_port
        yield self.destination_ip
        yield self.destination_port
        yield self.in_port

    def equals(self, flow: Flow):
        return (
            self.protocol == flow.protocol and
            self.source_ip == flow.source_ip and
            self.source_port == flow.source_port and
            self.destination_ip == flow.destination_ip and
            self.destination_port == flow.destination_port
        )
