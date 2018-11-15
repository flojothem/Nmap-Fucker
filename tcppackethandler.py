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
from scapy.all import *
from net_functions import *
from packet_functions import *
from random import *


class TcpPacketHandler():
    def __init__(self, nmap_pkts, ans_pkt, open_ports=[], closed_ports=[], filtered_ports=[], test_mode=False):
        self._raw_pkt = None
        self._tcp_pkt = None
        self._ip_pkt = None
        self._nmap_pkts = nmap_pkts

        self._must_op_port = open_ports
        self._must_closed_port = closed_ports
        self._must_filtered_ports = filtered_ports

        self._test_mode = test_mode

        self._ans = ans_pkt

    def new_packet(self, netfilter_pkt, scapy_pkt):
        self._tcp_pkt = scapy_pkt['TCP']
        self._ip_pkt = scapy_pkt['IP']
        self._raw_pkt = netfilter_pkt

        if self._test_mode:
            return self._check_packet()

        self._new_packet()

    def _new_packet(self):
        resultat = self._check_packet()

        if resultat == -1:
            self._react_no_nmap_pkt()
        else:
            if resultat[0] == 'steahlt_scan':
                self._scan_reaction()
            else:
                self._react_nmap_pkt(pkt_resultat=resultat)

    def _check_packet(self,):
        for seq in self._nmap_pkts:
            for index, pkt in enumerate(self._nmap_pkts.get(seq)):
                if self._check_tcp(nmap_pkt_tcp=pkt['TCP']) and self._check_ip(nmap_pkt=pkt['IP']):
                    return [seq, index]
        return -1

    def _check_ip(self, nmap_pkt):
        if nmap_pkt.flags == self._ip_pkt.flags and nmap_pkt.tos == self._ip_pkt.tos:
            return True
        return False

    def _check_tcp(self, nmap_pkt_tcp):
        if self._check_tcp_values(nmap_pkt_tcp) and self._check_tcp_options(nmap_pkt_tcp.options):
            return True
        return False

    def _check_tcp_options(self, pkt2_options):
        if self._tcp_pkt.options == pkt2_options:
            return True
        return False

    def _check_tcp_values(self, nmap_pkt):
        if not(nmap_pkt.flags == self._tcp_pkt.flags):
            return False
        if not(nmap_pkt.window == self._tcp_pkt.window):
            return False
        if not(nmap_pkt.urgptr == self._tcp_pkt.urgptr):
            return False

        return True

    def _react_nmap_pkt(self, pkt_resultat):
        self._drop_pkt()
        ans = copy.deepcopy(self._ans.get(pkt_resultat[0])[pkt_resultat[1]])

        if ans == -1:
            return

        ans['IP'].dst = self._ip_pkt.src
        ans['IP'].src = self._ip_pkt.dst
        ans['TCP'].dport = self._tcp_pkt.sport
        ans['TCP'].sport = self._tcp_pkt.dport

        ans = self._set_ack(ans)
        ans = self._set_seq(ans)
        send_ip_pkt(ans)

    def _set_ack(self, ans):
        if self._tcp_pkt.flags == 4 or ans['TCP'].ack == -1:
            ans['TCP'].ack = 0
        elif ans['TCP'].ack == -2:
            ans['TCP'].ack = self._tcp_pkt.seq
        elif ans['TCP'].ack == -4:
            ans['TCP'].ack = randint(4, 50000)
        else:
            ans['TCP'].ack = self._tcp_pkt.seq + 1

        return ans

    def _set_seq(self, ans):
        if ans['TCP'].seq == -1:
            ans['TCP'].seq = 0
        elif ans['TCP'].seq == -2:
            ans['TCP'].seq = self._tcp_pkt.ack
        elif ans['TCP'].seq == -3:
            ans['TCP'].seq = self._tcp_pkt.ack + 1
        return ans

    def _get_timestamp_option(self, ans_pkt):
        options = ans_pkt['TCP'].options
        for index, op in enumerate(options):
            if op[0] == 'Timestamp':
                if not(op[1][0] == 0 and op[1][1] == 0):
                    return [op, index]
        return None

    def _react_no_nmap_pkt(self):

        self._accept_pkt()

# ###################################################################################################################
#port-scan - STUFF

    def _scan_reaction(self):
        if self._tcp_pkt.dport in self._must_closed_port:
            self._closed_port()
        elif self._tcp_pkt.dport in self._must_op_port:
            self._open_port()
        elif self._tcp_pkt.dport in self._must_filtered_ports:
            self._filtered_port()
        else:
            self._do_nothing()

    def _open_port(self):
        self._drop_pkt()
        resp_pkt = (IP(dst=self._ip_pkt.src,src=self._ip_pkt.dst)/TCP(dport=self._tcp_pkt.sport,sport=self._tcp_pkt.dport,ack=self._tcp_pkt.seq+1,flags='SA'))
        send_ip_pkt(resp_pkt)

    def _closed_port(self):
        self._drop_pkt()
        resp_pkt = (IP(dst=self._ip_pkt.src,src=self._ip_pkt.dst)/TCP(dport=self._tcp_pkt.sport,sport=self._tcp_pkt.dport,ack=self._tcp_pkt.seq+1,flags='RS'))
        send_ip_pkt(resp_pkt)

    def _filtered_port(self):
        self._drop_pkt()

    def _do_nothing(self):
        self._accept_pkt()

#####################################################################################################################

    def _accept_pkt(self):
        accept_pkt(pkt=self._raw_pkt)

    def _drop_pkt(self):
        drop_pkt(pkt=self._raw_pkt)