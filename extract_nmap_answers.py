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

from einlesen_wireshark import *
from argparse import ArgumentParser


def get_parser():
    parser = ArgumentParser()
    parser.add_argument('-ho', dest='hops', type=int, default=0, help='Anzahl des Wertes der auf den ttl addiert werden soll')
    parser.add_argument('-fp', dest='file_path', type=str, help='Pfad unter dem die extrahierten Antworten verfügbar sein sollen')
    parser.add_argument('-pp', dest='pcap_path', type=str, help='Pfad unter dem das pcap zu finden ist aus dem die Antworten extrahiert werden solln')
    return parser


if __name__ == '__main__':
    args = get_parser().parse_args()
    ExtractAnswerPkts(file_name=args.file_path, pcap_path=args.pcap_path, hops=args.hops).start()