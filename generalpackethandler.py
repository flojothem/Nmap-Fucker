############
# Nmap-Fucker
#Copyright (C) 2018  Florian Nettersheim

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.
#############

from netfilterqueue import NetfilterQueue
from tcppackethandler import *
from icmppackethandler import *
from udppackethandler import *
from packet_functions import *
from scapy.all import *


class GeneralPacketHandler():
    def __init__(self, queue_num, handler_type, cl_ports, op_ports, fil_ports, ans_path):
        self._queue_num = queue_num
        self._nfqueue = NetfilterQueue()
        self._nmap_pkts = build_nmap_pkts()
        self._ans_pkts = build_test_answer_from_file(ans_path)
        self._handler = self._init_handler(handler_type, cl_ports, op_ports, fil_ports)

    def _init_handler(self, handler_type, cl_ports, op_ports, fil_ports):
        if handler_type == 'tcp':
            return TcpPacketHandler(nmap_pkts=self._nmap_pkts.get('tcp'), open_ports=op_ports, closed_ports=cl_ports, filtered_ports=fil_ports, ans_pkt=self._ans_pkts)
        if handler_type == 'icmp':
            return IcmpPacketHandler(nmap_pkts=self._nmap_pkts.get('icmp'), ans_pkt=self._ans_pkts)
        if handler_type == 'udp':
            return UdpPacketHandler(nmap_pkts=self._nmap_pkts.get('udp'), ans_pkt=self._ans_pkts)

    def work(self, raw_pkt):
        ip_pkt = IP(bytes(raw_pkt.get_payload()))
        self._handler.new_packet(netfilter_pkt=raw_pkt, scapy_pkt=ip_pkt)

    def start(self):
        self._nfqueue.run()

    def bind_queue(self):
        self._nfqueue.bind(self._queue_num, self.work)

    def unbind_queue(self):
        self._nfqueue.unbind()





