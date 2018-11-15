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

from scapy.all import *
from net_functions import *
from packet_functions import *


class IcmpPacketHandler():
    def __init__(self, nmap_pkts,  ans_pkt, test_mode=False):
        self._raw_pkt = None
        self._icmp_pkt = None
        self._ip_pkt = None
        self._nmap_pkts = nmap_pkts

        self._test_mode =test_mode

        self._ans = ans_pkt

    def new_packet(self, netfilter_pkt, scapy_pkt):
        self._raw_pkt = netfilter_pkt
        self._icmp_pkt = scapy_pkt['ICMP']
        self._ip_pkt = scapy_pkt['IP']

        if self._test_mode:
            return self._check_packet()

        self._new_packet()

    def _new_packet(self):
        resultat = self._check_packet()
        if resultat == -1:
            self._react_no_nmap_pkt()
        else:
            self._react_nmap_pkt(resultat)

    def _check_packet(self):
        for seq in self._nmap_pkts:
            for index, pkt in enumerate(self._nmap_pkts.get(seq)):
                if self._check_ip(nmap_pkt=pkt['IP']) and self._check_icmp(nmap_pkt=pkt['ICMP']):
                    return [seq, index]
        return -1

    def _check_ip(self, nmap_pkt):
        if nmap_pkt.flags == self._ip_pkt.flags and nmap_pkt.tos == self._ip_pkt.tos:
            return True
        return False

    def _check_icmp(self, nmap_pkt):
        if nmap_pkt.type == self._icmp_pkt.type and nmap_pkt.code == self._icmp_pkt.code and nmap_pkt.seq == self._icmp_pkt.seq:
            return True
        return False

    def _react_no_nmap_pkt(self):
        self._accept_pkt()

    def _react_nmap_pkt(self, pkt_resultat):
        self._drop_pkt()
        ans = copy.deepcopy(self._ans.get(pkt_resultat[0])[pkt_resultat[1]])

        if ans == -1:
            return

        ans['IP'].src = self._ip_pkt.dst
        ans['IP'].dst = self._ip_pkt.src
        ans['ICMP'].id = self._icmp_pkt.id
        ans['ICMP'].seq = self._icmp_pkt.seq
        send_ip_pkt(ans)

    def _accept_pkt(self):
        accept_pkt(pkt=self._raw_pkt)

    def _drop_pkt(self):
        drop_pkt(pkt=self._raw_pkt)











