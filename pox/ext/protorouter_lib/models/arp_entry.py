class ArpEntry:
    def __init__(self, mac: str, switch_openflow_port: int, port_type: str):
        self.mac = mac
        self.switch_openflow_port = switch_openflow_port
        self.port_type = port_type
