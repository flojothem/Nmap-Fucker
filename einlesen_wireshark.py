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
from tcppackethandler import *
from icmppackethandler import *
from udppackethandler import *
from packet_functions import *


class ExtractAnswerPkts():
    def __init__(self,file_name, pcap_path, hops):
        self._namp_pkts = build_nmap_pkts()
        self._packets = rdpcap(pcap_path)
        self._tcp_handler = TcpPacketHandler(nmap_pkts=self._namp_pkts['tcp'], test_mode=True, ans_pkt=None)
        self._icmp_handler = IcmpPacketHandler(nmap_pkts=self._namp_pkts['icmp'], test_mode=True, ans_pkt=None)
        self._udp_handler = UdpPacketHandler(nmap_pkts=self._namp_pkts['udp'], test_mode=True, ans_pkt=None)
        self._hops = hops

        self._file_name = file_name

        self.erg = ""

        self._already_see = {'seq_1': [0, 0, 0, 0, 0, 0],
                             'seq_2': [0, 0],
                             'seq_3': [0],
                             'seq_4': [0, 0, 0, 0, 0, 0],
                             'seq_5': [0]}

    def start(self):
        file = open(self._file_name, 'w')
        for index, pkt in enumerate(self._packets):
            self.analyse_pkt(pkt, index)
        file.write(self.erg)
        file.close()

    def analyse_pkt(self, pkt, index):
        if 'TCP' in pkt:
            resultat = self._tcp_handler.new_packet(netfilter_pkt=None, scapy_pkt=pkt)
            if not resultat == -1:
                a_pkt = self._found_tcp(pkt, index)
                if not a_pkt == -1:
                    if self._already_see.get(resultat[0])[resultat[1]] == 0:
                            self._del_ip_fields(a_pkt['IP'])
                            self._del_tcp_fields(a_pkt['TCP'])
                            self.set_ttl(resp_pkt=a_pkt)
                            stra = 'pkt:\n{0} {1}\n {2}\n\n'.format(resultat[0], resultat[1], a_pkt['IP'].command())
                            self.erg += stra
                            self._already_see.get(resultat[0])[resultat[1]] = 1

                elif self._already_see.get(resultat[0])[resultat[1]] == 0:
                    self._already_see.get(resultat[0])[resultat[1]] = 1
                    self.erg += 'pkt:\n{} {}\nNone\n\n'.format(resultat[0], resultat[1])
                return

        elif 'UDP' in pkt:
            resultat = self._udp_handler.new_packet(netfilter_pkt=None,scapy_pkt=pkt)
            if not resultat == -1:
                a_pkt = self._found_udp(pkt, index)
                self._del_ip_fields(a_pkt['IP'])
                if not resultat == -1:
                    self.set_ttl(resp_pkt=a_pkt)
                    stra = 'pkt:\n{0} {1}\n {2}\n\n'.format(resultat[0], resultat[1], a_pkt['IP'].command())
                    self.erg += stra

        elif 'ICMP' in pkt:
            resultat = self._icmp_handler.new_packet(netfilter_pkt=None,scapy_pkt=pkt)
            if not resultat == -1:
                a_pkt = self._found_icmp(pkt,index)
                self._del_icmp_fields(pkt)
                if not a_pkt == -1:
                    self._del_ip_fields(a_pkt['IP'])
                    self._del_icmp_fields(pkt['ICMP'])
                    self.set_ttl(resp_pkt=a_pkt)
                    stra = 'pkt:\n{0} {1}\n {2}\n\n'.format(resultat[0], resultat[1], a_pkt['IP'].command())
                    self.erg += stra

    def _del_ip_fields(self, pkt):
        del(pkt.ihl)
        del(pkt.len)
        del(pkt.chksum)
        del(pkt.dst)
        del(pkt.src)

    def _del_tcp_fields(self, pkt):
        del(pkt.dport)
        del(pkt.sport)
        del(pkt.chksum)
        del(pkt.dataofs)
        del(pkt.reserved)

    def _del_icmp_fields(self, pkt):
        del(pkt.chksum)

    def _found_tcp(self, req_pkt, index):
        dport = req_pkt['TCP'].dport
        sport = req_pkt['TCP'].sport

        for pkt in self._packets[index:]:
            if 'TCP' in pkt:
                if pkt['TCP'].dport == sport and pkt['TCP'].sport == dport:
                    pkt['TCP'].ack = self.test_a(resp_pkt=pkt['TCP'], req_pkt=req_pkt['TCP'])
                    pkt['TCP'].seq = self.test_s(resp_pkt=pkt['TCP'], req_pkt=req_pkt['TCP'])
                    return pkt
        return -1

    def test_s(self, resp_pkt, req_pkt):
        if resp_pkt.seq == 0:
            return -1
        if resp_pkt.seq == req_pkt.ack:
            return -2
        if resp_pkt.seq == req_pkt.ack+1:
            return -3
        return resp_pkt.seq

    def test_a(self, resp_pkt,req_pkt):
        if resp_pkt.ack == 0:
            return -1
        if resp_pkt.ack == req_pkt.seq:
            return -2
        if resp_pkt.ack == req_pkt.seq+1:
            return -3
        return resp_pkt.ack

    def set_ttl(self, resp_pkt):
        resp_pkt['IP'].ttl = resp_pkt['IP'].ttl + self._hops

    def test_ruck(self, resp_pkt, req_pkt):
        if resp_pkt['UDP in ICMP'].chksum == req_pkt['UDP'].chksum:
            resp_pkt['UDP in ICMP'].chksum = -1
        return resp_pkt

    def _found_udp(self, req_pkt, index):
        dport = req_pkt['UDP'].dport
        sport = req_pkt['UDP'].sport

        dip = req_pkt['IP'].dst
        sip = req_pkt['IP'].src

        for pkt in self._packets[index:]:
            if'ICMP' in pkt and pkt['ICMP'].type == 3:
                if pkt['UDP in ICMP'].dport == dport and pkt['UDP in ICMP'].sport == sport and pkt['IP'].src == dip and pkt['IP'].dst == sip:
                    return self.test_ruck(pkt, req_pkt)

        return -1

    def _found_icmp(self, pkt, index):
        dip = pkt['IP'].dst
        sip = pkt['IP'].src

        for pkt in self._packets[index:]:
            if 'ICMP' in pkt:
                if pkt['IP'].dst == sip and pkt['IP'].src == dip:
                    return pkt
        return -1



