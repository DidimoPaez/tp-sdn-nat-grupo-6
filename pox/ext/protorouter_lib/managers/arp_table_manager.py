from typing import Dict, List, Tuple

from pox.ext.protorouter_lib.utils.logger import Logger
from pox.lib.addresses import EthAddr, IPAddr

from protorouter_lib.models.arp_entry import ArpEntry
from protorouter_lib.models.pending_packet import PendingPacket
from ext.protorouter_lib.constants import *


class ArpTableManager:
    def __init__(self, private_network: IPAddr, private_mask: int):
        self.private_network: IPAddr = private_network
        self.private_mask: int = private_mask
        self.table: Dict[IPAddr, ArpEntry] = dict()
        self.pending: Dict[IPAddr, List[PendingPacket]] = dict()

    def contains(self, ip_addr) -> bool:
        return IPAddr(ip_addr) in self.table

    def get(self, ip_addr) -> ArpEntry:
        return self.table.get(IPAddr(ip_addr))

    def try_put(self, ip_addr, mac_addr, in_port) -> Tuple[ArpEntry, bool]:
        ip_addr = IPAddr(ip_addr)
        existing = self.table.get(ip_addr)
        if existing is not None:
            return existing, False

        port_type = (
            PRIVATE
            if ip_addr.inNetwork(self.private_network, self.private_mask)
            else PUBLIC
        )
        entry = ArpEntry(EthAddr(mac_addr), in_port, port_type)
        self.table[ip_addr] = entry
        return entry, True

    def learn_arp_entry(self, in_port, ip_addr, mac_addr):
        entry, is_new = self.try_put(ip_addr, mac_addr, in_port)
        if is_new:
            Logger.info_cyan(f"ARP learned: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} | type={entry.port_type}")
        else:
            Logger.info_cyan(f"ARP already exists: {IPAddr(ip_addr)} -> {entry.mac} | port={in_port} ")

    def queue_pending(self, ip_addr, pending_packet) -> bool:
        ip_addr = IPAddr(ip_addr)
        is_first_for_this_ip = ip_addr not in self.pending
        self.pending.setdefault(ip_addr, []).append(pending_packet)
        return is_first_for_this_ip

    def pop_pending(self, ip_addr) -> list:
        return self.pending.pop(IPAddr(ip_addr), [])

    def has_pending(self, ip_addr) -> bool:
        return IPAddr(ip_addr) in self.pending
