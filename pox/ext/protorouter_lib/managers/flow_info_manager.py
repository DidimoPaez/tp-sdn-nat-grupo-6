from ext.protorouter_lib.managers.controller_config import ControllerConfig
from pox.ext.protorouter_lib.constants import *
from pox.ext.protorouter_lib.models.flow import Flow
from pox.pox.lib.packet.ethernet import ethernet


class FlowInfoManager:
    def __init__(self):
        self.cfg: ControllerConfig = ControllerConfig.get()

    def get_transport_protocol(self, packet: ethernet):
        udp_packet = packet.find(PROTO_UDP)
        tcp_packet = packet.find(PROTO_TCP)

        protocol = None
        transport_packet = None

        if udp_packet is not None:
            protocol = PROTO_UDP
            transport_packet = udp_packet
        elif tcp_packet is not None:
            protocol = PROTO_TCP
            transport_packet = tcp_packet
        return (protocol, transport_packet,)

    def extract_flow_info(self, eth_packet, in_port):
        ip_packet = eth_packet.payload

        protocol, transport_packet = self.get_transport_protocol(eth_packet)
        if transport_packet is None:
            return None

        host_private_ip = ip_packet.srcip
        if not IPAddr(host_private_ip).inNetwork(
            self.cfg.nat_private_net, self.cfg.nat_private_mask
        ):
            return None

        return Flow(
            protocol,                   # Transport protocol
            eth_packet.src,             # MAC Address
            host_private_ip,            # Source IP, client hosts'
            transport_packet.srcport,   # Source port, client hosts'
            in_port,                    # OpenFlow private port
            ip_packet.dstip,            # Destination IP, server host's
            transport_packet.dstport    # Destination port, server host's
        )
