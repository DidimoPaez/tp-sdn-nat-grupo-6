from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ext.protorouter_lib.managers.nat_manager import NatTableManager

import pox.openflow.libopenflow_01 as of

from ext.protorouter_lib.constants import *
from ext.protorouter_lib.managers.controller_config import ControllerConfig
from ext.protorouter_lib.utils.logger import Logger


class FlowManager:
    def __init__(self, connection, nat_table_manager: NatTableManager):
        self.cfg = ControllerConfig.get()
        self.connection = connection
        self.nat_table_manager: NatTableManager = nat_table_manager

    def handle_remove_incoming(self, match):
        nat_public_port = match.tp_dst
        self.nat_table_manager.handle_flow_removed_incoming(nat_public_port)
        Logger.info_yellow(
            f"Flujo entrante removido por el switch (puerto público {nat_public_port})"
        )

    def handle_remove_outgoing(self, match):
        protocol = IP_NUMBER_TO_PROTO.get(match.nw_proto)
        if protocol is None:
            return
        self.nat_table_manager.handle_flow_removed_outgoing(
            protocol, match.nw_src, match.tp_src, match.nw_dst, match.tp_dst
        )
        Logger.info_yellow(f"Flujo saliente removido por el switch ({match.nw_src}:{match.tp_src} -> {match.nw_dst}:{match.tp_dst})")

    def handle_flow_removed(self, event):
        Logger.info_red(f"_handle_FlowRemoved has been called")
        match = event.ofp.match

        if match.nw_dst == self.cfg.nat_public_ip:
            self.handle_remove_incoming(match)
        else:
            self.handle_remove_outgoing(match)

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
