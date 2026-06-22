from collections import namedtuple

from pox.lib.addresses import EthAddr, IPAddr



PRIVATE: str = "private"
PUBLIC: str = "public"

# MAC addr Ethernet mide 48 bits
MAC_ETHER_LENGTH: int = 6

# Dirección IPv4 mide 32 bits
IP_ADDR_LENGTH: int = 4

MAC_UNKNOWN: str = "00:00:00:00:00:00"
ETHER_BROADCAST: str = "ff:ff:ff:ff:ff:ff"

TIME_OUT: int = 60
STATE_PENDING_ARP = "Pending ARP"
STATE_INSTALLED = "Installed"

INITIAL_ASSIGNED_PORT: int = 10000

PROTO_TCP = "tcp"
PROTO_UDP = "udp"
PROTO_IP_NUMBER = {
    PROTO_TCP: 6,
    PROTO_UDP: 17,
}

# Nombre de protocolo interno
IP_NUMBER_TO_PROTO = {v: k for k, v in PROTO_IP_NUMBER.items()}

# Red interna
PRIVATE_SUBNET = IPAddr("192.168.1.0")

# Máscara de la red interna
PRIVATE_MASK = 24

# IP del router en la red privada
PRIVATE_IP = IPAddr("192.168.1.254")

# IP del router en la red pública
PUBLIC_IP = IPAddr("200.0.0.254")

# MAC del router hacia la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")

# MAC del router hacia la red privada
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")

# Puerto del switch conectado a la red pública
PUBLIC_PORT = 1

# MAC del host externo (TODO: resolver mediante ARP)
H1_MAC = EthAddr(
    "00:00:00:00:00:01"
)
