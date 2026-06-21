PRIVATE: str = "private"
PUBLIC: str = "public"

MAC_ETHER_LENGTH: int = 6  # MAC addr Ethernet mide 48 bits
IP_ADDR_LENGTH: int = 4  ##dirección IPv4 mide 32 bits

MAC_UNKNOWN: str = "00:00:00:00:00:00"
ETHER_BROADCAST: str = "ff:ff:ff:ff:ff:ff"

TIME_OUT: int = 10
STATE_PENDING_ARP = "Pending ARP"
STATE_INSTALLED = "Installed"

INITIAL_ASSIGNED_PORT: int = 10000

PROTO_TCP = "tcp"
PROTO_UDP = "udp"
PROTO_IP_NUMBER = {
    PROTO_TCP: 6,
    PROTO_UDP: 17,
}
IP_NUMBER_TO_PROTO = {v: k for k, v in PROTO_IP_NUMBER.items()} # nombre de protocolo interno.