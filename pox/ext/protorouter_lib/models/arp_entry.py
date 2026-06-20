import time

from protorouter_lib.constants import STATE_INSTALLED, STATE_PENDING_ARP, TIME_OUT
class ArpEntry:
    def __init__(self, mac: str, switch_openflow_port: int, port_type: str):
        self.mac = mac
        self.switch_openflow_port = switch_openflow_port
        self.port_type = port_type
        self.last_seen = time.monotonic()
        self.idle_timeout: int = TIME_OUT 

    # Funciones parecidas a las de NatEntry
    def touch(self):
        self.last_seen = time.monotonic()

    def update(self, mac, switch_openflow_port: int, port_type: str):
        self.mac = mac
        self.switch_openflow_port = switch_openflow_port
        self.port_type = port_type
        self.touch()

    def is_stale(self) -> bool:
        return (time.monotonic() - self.last_seen) > self.idle_timeout
    
    def __repr__(self):
        return (
            "ArpEntry("
            f"mac={self.mac}, "
            f"switch_openflow_port={self.switch_openflow_port}, "
            f"port_type={self.port_type}"
            ")"
        )
