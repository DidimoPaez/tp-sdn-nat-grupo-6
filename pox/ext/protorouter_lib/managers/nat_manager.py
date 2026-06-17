"""
NatManager

Por ahora sólo se extrajo de ProtoRouter la asignación de puertos
públicos (lo que antes era self.next_nat_public_port / self.assigned_ports),
para que esa lógica quede en un solo lugar.
La ideas es que aca tambien esten los metodos de pregutna y respuesta tambien.
.
"""


class NatManager:
    def __init__(self, initial_port: int):
        self._next_port = initial_port
        self._assigned_ports: set = set()

    def assign_public_port(self) -> int:
        port = self._next_port
        self._assigned_ports.add(port)
        self._next_port += 1
        return port

