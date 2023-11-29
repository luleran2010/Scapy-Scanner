#!/usr/bin/python
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

ip = '192.168.33.129'
ports = (1,1024)
flags = 'S'

ans, unans = sr(IP(dst=ip)/TCP(dport=ports, flags=flags),
         retry=1, timeout=1, threaded=True, verbose=0)

tcp_ans = ans.filter(lambda s, r: r.haslayer(TCP))

sa_ans = tcp_ans.filter(lambda s, r: r[TCP].flags == 'SA')
sa_ports = [i.answer[IP].sport for i in sa_ans]
sr(IP(dst=ip)/TCP(dport=sa_ports, flags='R'), timeout=1, verbose=0)

r_ans = tcp_ans.filter(lambda s, r: r[TCP].flags.R)
           
icmp_ans = ans.filter(lambda s,r: r.haslayer(ICMP))
unreachable_ans = icmp_ans.filter(
    lambda s, r: r[ICMP].type == 3 and
                 int(r[ICMP].code) in [1, 2, 3, 9, 10, 13]
)

open_ans = sa_ans
closed_ans = r_ans
filtered_ans = unans + unreachable_ans
unfiltered_ans = []

print('open:', len(open_ans))
print('closed:', len(closed_ans))
print('filtered:', len(filtered_ans),
      '(unanswered:', len(unans), 'unreachable:', len(unreachable_ans), ')')
print('unfiletered:', len(unfiltered_ans))

print('port\tstatus\tservice')
open_ans.summary(
    lambda s, r: r.sprintf('%r,TCP.sport%\topen\t%TCP.sport%')
)
