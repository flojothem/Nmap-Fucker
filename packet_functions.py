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
from readinanswers import *


def build_nmap_pkts():
    nmap_pkt_tcp = {'seq_1': [IP() /TCP(options = [('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], window=1, flags=2),
                            IP() / TCP(options=[('MSS', 1400), ('WScale', 0), ('SAckOK', b''), ('Timestamp', (4294967295, 0)), ('EOL', None)], window=63, flags=2),
                            IP() / TCP(options=[('Timestamp', (4294967295, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 640)], window=4, flags=2),
                            IP() / TCP(options=[('SAckOK', b''), ('Timestamp', (4294967295, 0)), ('WScale', 10), ('EOL', None)],window=4, flags=2),
                            IP() / TCP(options=[('MSS', 536), ('SAckOK', b''), ('Timestamp', (4294967295, 0)), ('WScale', 10), ('EOL', None)], window=16, flags=2),
                            IP() / TCP(options=[('MSS', 265), ('SAckOK', b''), ('Timestamp', (4294967295, 0))], window=512,flags=2)],
                    'seq_3': [IP()/TCP(options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', b''), ('NOP', None), ('NOP', None)], flags='SEC', urgptr=63477, window=3)],
                    'seq_4': [(IP(flags=2)/TCP(options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], flags=0, window=128)),
                             (IP() / TCP(options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], flags='SFUP', window=256)),
                             (IP(flags=2) / TCP(options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], flags='A', window=1024)),
                             (IP(flags=0) / TCP(options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], window=31337, flags='S')),
                             (IP(flags=2) / TCP(options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], flags='A', window=32768)),
                             (IP() / TCP(options=[('WScale', 15), ('NOP', None), ('MSS', 265), ('Timestamp', (4294967295, 0)), ('SAckOK', b'')], flags='FPU', window=65535))],
                    'steahlt_scan': (IP()/TCP(flags=2, options=[('MSS', 1460)], window=1024))}

    nmap_pkt_icmp = {'seq_2': [(IP(flags=2, tos=0)/ICMP(type=8, seq=295, code=9)),
                              (IP(flags=0, tos=4) / ICMP(type=8, seq=296, code=0))]}

    nmap_pkt_udp = {'seq_5': [(IP(id=4162)/UDP()/Raw(load=b'\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43\x43'))]}

    return {'tcp': nmap_pkt_tcp, 'icmp': nmap_pkt_icmp, 'udp': nmap_pkt_udp}


def build_test_answer():
        return {'seq_1': [(IP(id=61829, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798979, options=[('MSS', 1460), ('NOP', None), ('WScale', 0), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('NOP', None), ('Timestamp', (257200, 4294967295))], seq=2791662381, window=8688)),
                            (IP(id=62153, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798980, options=[('MSS', 1400), ('NOP', None), ('WScale', 0), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('NOP', None), ('Timestamp', (257300, 4294967295))], seq=3433129393, window=8328)),
                            (IP(id=62399, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798981, options=[('MSS', 640), ('NOP', None), ('WScale', 0), ('NOP', None), ('NOP', None), ('Timestamp', (257400, 4294967295))], seq=679111803, window=8792)),
                            (IP(id=63084, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798982, options=[('MSS', 1460), ('NOP', None), ('WScale', 0), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('NOP', None), ('Timestamp', (257500, 4294967295))], seq=257331060, window=8688)),
                            (IP(id=63480, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798983, options=[('MSS', 536), ('NOP', None), ('WScale', 0), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('NOP', None), ('Timestamp', (257600, 4294967295))], seq=3938840204, window=8384)),
                            (IP(id=63836, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798984, options=[('MSS', 265), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('NOP', None), ('Timestamp', (257700, 4294967295))], seq=1488048519, window=8349))],

                   'seq_2': [(IP(id=12556, tos=0, version=4, flags=0, ttl=255, proto=1, options=[])/ICMP(type=0, seq=295, code=9, id=63366)/Raw(load=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')),
                            (IP(id=53758, tos=4, version=4, flags=0, ttl=255, proto=1, options=[])/ICMP(type=0, seq=296, code=0, id=63367)/Raw(load=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))],

                   'seq_3': [(IP(id=63084, tos=0, version=4, flags=0, ttl=64, proto=6, frag=0, options=[])/TCP(urgptr=0, flags=18, ack=3683798979, options=[('MSS', 1460), ('NOP', None), ('WScale', 0), ('NOP', None), ('NOP', None), ('SAckOK', b'')], seq=2984937324, window=8760))],

                   'seq_4': [None,None,
                            (IP(id=1066, options=[], proto=6, ttl=64, version=4, tos=0, flags=0, frag=0)/TCP(flags=4, urgptr=0, seq=4256518101, ack=0, window=0)/Padding(load=b'\x00\x00\x00\x00\x00\x00')),
                            (IP(id=1415, options=[], proto=6, ttl=64, version=4, tos=0, flags=0, frag=0)/TCP(flags=20, urgptr=0, seq=2673292076, ack=0, window=0)/Padding(load=b'\x00\x00\x00\x00\x00\x00')),
                            (IP(id=1785, options=[], proto=6, ttl=64, version=4, tos=0, flags=0, frag=0)/TCP(flags=4, urgptr=0, seq=4256518101, ack=0, window=0)/Padding(load=b'\x00\x00\x00\x00\x00\x00')),
                            (IP(id=2240, options=[], proto=6, ttl=64, version=4, tos=0, flags=0, frag=0)/TCP(flags=20, urgptr=0, seq=0, ack=0, window=0)/Padding(load=b'\x00\x00\x00\x00\x00\x00'))],

                   'seq_5': [(IP(id=63084, tos=0, version=4, flags=0, ttl=255, proto=1,  options=[])/ICMP(type=3, chksum=64821, seq=None, reserved=None, ts_rx=None, code=3)/IPerror(len=328, tos=0, version=4, chksum=56537, flags=0, proto=17, frag=0, options=[], id=4162)/UDPerror(len=308))]}


def build_test_answer_from_file(file_path):
    return ReadInAnswers(file_path).start()