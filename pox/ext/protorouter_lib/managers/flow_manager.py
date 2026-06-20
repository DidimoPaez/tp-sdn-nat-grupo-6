import pox.openflow.libopenflow_01 as of

from ext.protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger


class FlowManager:
    def __init__(self, connection):
        self.cfg = ControllerConfig.get()
        self.connection = connection

    def install_flows(self, nat_entry):
        ip_proto = PROTO_IP_NUMBER.get(nat_entry.protocol)
        if ip_proto is None:
            Logger.info_red(f"[ERROR] Protocolo desconocido para instalar flujo: {nat_entry.protocol}",)
            return

        # Instalar Flujo Saliente
        fm = of.ofp_flow_mod()
        fm.idle_timeout = nat_entry.idle_timeout
        fm.flags = of.OFPFF_SEND_FLOW_REM

        # Filtro (Saliente)
        fm.match.dl_type = 0x800  # IPv4
        fm.match.in_port = nat_entry.private_openflow_port
        fm.match.nw_proto = ip_proto
        fm.match.nw_src = nat_entry.host_private_ip
        fm.match.nw_dst = nat_entry.host_public_ip
        fm.match.tp_src = nat_entry.host_private_port
        fm.match.tp_dst = nat_entry.host_public_port

        # Acción (Saliente)
        fm.actions.append(of.ofp_action_dl_addr.set_src(self.cfg.nat_public_mac))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(nat_entry.host_public_mac))
        fm.actions.append(of.ofp_action_nw_addr.set_src(self.cfg.nat_public_ip))
        fm.actions.append(of.ofp_action_tp_port.set_src(nat_entry.nat_public_port))
        fm.actions.append(of.ofp_action_output(port=nat_entry.public_openflow_port))
        self.connection.send(fm)

        # Instalar Flujo Entrante (para respuesta)
        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = nat_entry.idle_timeout
        fm_back.flags = of.OFPFF_SEND_FLOW_REM

        # Filtro (Entrante)
        fm_back.match.dl_type = 0x800  # IPv4
        fm_back.match.in_port = nat_entry.public_openflow_port
        fm_back.match.nw_proto = ip_proto
        fm_back.match.nw_src = nat_entry.host_public_ip
        fm_back.match.nw_dst = self.cfg.nat_public_ip
        fm_back.match.tp_src = nat_entry.host_public_port
        fm_back.match.tp_dst = nat_entry.nat_public_port

        # Acción (Entrante)
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(self.cfg.nat_private_mac))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(nat_entry.host_private_mac))
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(nat_entry.host_private_ip))
        fm_back.actions.append(of.ofp_action_tp_port.set_dst(nat_entry.host_private_port))
        fm_back.actions.append(of.ofp_action_output(port=nat_entry.private_openflow_port))
        self.connection.send(fm_back)

        Logger.info_green(
            f"Flujos instalados para puerto público {nat_entry.nat_public_port}"
        )
