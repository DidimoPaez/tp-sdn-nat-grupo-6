from typing import Dict, List

from pox.pox.lib.addresses import IPAddr

from ext.protorouter_lib.models.pending_packet import PendingPacket

class PendingPacketManager:
    def __init__(self):
        self.pending: Dict[IPAddr, List[PendingPacket]] = dict()

    def contains_binded(self, ip_addr) -> bool:
        return IPAddr(ip_addr) in self.pending

    def bind(self, pending_packet: PendingPacket, ip_addr) -> bool:
        ip_addr = IPAddr(ip_addr)
        self.pending.setdefault(ip_addr, []).append(pending_packet)

    def pop_all_binded(self, ip_addr) -> list:
        return self.pending.pop(IPAddr(ip_addr), [])
