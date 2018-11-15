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


class ReadInAnswers():
    def __init__(self,file_path):
        self._file_path = file_path
        self.answeres = {}

    def start(self):
        with open(self._file_path) as file:
            txt = file.readlines()
            i = 0
            while i < len(txt):
                line = txt[i]
                if line == 'pkt:\n':
                    self._extrakt_okt(seq_line=txt[i+1], pkt_line=txt[i+2])
                    i += 2
                    continue

                i += 1

        return self.answeres

    def _extrakt_okt(self,seq_line,pkt_line):
        seq, pkt_nr = seq_line.split(' ')
        if seq in self.answeres:
            if pkt_line == 'None\n':
                self.answeres.get(seq).append(-1)
            else:
                self.answeres.get(seq).append(eval(pkt_line))
        else:
            if pkt_line == 'None\n':
                self.answeres.update({seq: [-1]})
            else:
                self.answeres.update({seq: [eval(pkt_line)]})



