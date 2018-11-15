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


import multiprocessing
from os import system
from argparse import ArgumentParser
from generalpackethandler import *
import time


def get_parser():
    parser = ArgumentParser()
    parser.add_argument('-a', dest='ans_path', required=True, type=str,  help='Nmap Antworten')
    parser.add_argument('-cp', dest='cl_ports', default=[], nargs='*', type=int, help='Sämtliche Ports die aus Sicht von Nmap den Status geschlossen besitzen sollen')
    parser.add_argument('-op', dest='op_ports', default=[], nargs='*', type=int, help='Sämtliche Ports die aus Sicht von Nmap den Status offen besitzen sollen')
    parser.add_argument('-fp', dest='fil_ports', default=[], nargs='*', type=int, help='Sämtliche Ports die aus Sicht von Nmap den Status gefilteret besitzen sollen')
    return parser


def build_iptables_commands():
    cmds = []
    cmds.append(tcp_cmd(1))
    cmds.append(tcp_cmd(2))
    cmds.append(icmp_cmd(3))
    cmds.append(udp_cmd(4))
    return cmds


def tcp_cmd(i):
    set_t = 'iptables -A INPUT -p tcp -m statistic  --mode nth --every {} --packet 0  -j NFQUEUE --queue-num {}'.format(i, i)
    remove = 'iptables -D INPUT -p tcp -m statistic  --mode nth --every {} --packet 0  -j NFQUEUE --queue-num {}'.format(i, i)
    return (set_t, 'tcp', i), remove


def udp_cmd(i):
    set_t = 'iptables -A INPUT -p udp -m statistic  --mode nth --every {} --packet 0  -j NFQUEUE --queue-num {}'.format(1, i)
    remove = 'iptables -D INPUT -p udp -m statistic  --mode nth --every {} --packet 0  -j NFQUEUE --queue-num {}'.format(1, i)
    return (set_t, 'udp', i), remove


def icmp_cmd(i):
    set_t = 'iptables -A INPUT -p icmp -m statistic  --mode nth --every {} --packet 0  -j NFQUEUE --queue-num {}'.format(1, i)
    remove = 'iptables -D INPUT -p icmp -m statistic  --mode nth --every {} --packet 0  -j NFQUEUE --queue-num {}'.format(1, i)
    return (set_t, 'icmp', i), remove


def remove_iptables(cmds):
    for cmd in cmds:
        system(cmd[1])


def set_up_iptables(cmd):
    system(cmd)


def arg_parser(args):
    return args.cl_ports, args.op_ports, args.fil_ports, args.ans_path


def start():
    cl_ports, op_ports, fil_ports,  ans_path = arg_parser(get_parser().parse_args())
    cmds = build_iptables_commands()

    processes = []
    for com in cmds:
        set_up_iptables(com[0][0])
        proc = start_process(com[0][2], com[0][1], cl_ports, fil_ports, op_ports, ans_path)
        processes.append(proc)
        proc.start()
    try:
        while True:
            time.sleep(120)
    except KeyboardInterrupt:
        for pro in processes:
            pro.terminate()
        remove_iptables(cmds)


def start_process(q_counter, handler_type, cl_ports, fil_ports, op_ports, ans_path):
    return multiprocessing.Process(target=start_q, args=(q_counter, handler_type, cl_ports, fil_ports, op_ports, ans_path))


def start_q(q_n, handler_type, cl_ports, fil_ports, op_ports, ans_path):
    print('start queue handler {}'.format(q_n))
    handler = GeneralPacketHandler(q_n, handler_type, cl_ports, op_ports, fil_ports, ans_path)

    try:
        handler.bind_queue()
        handler.start()

    except KeyboardInterrupt:
        handler.unbind_queue()
        print('end queue handler {}'.format(q_n))


if __name__ == '__main__':
    print('start multi script')
    start()
    print('ende multiscript')