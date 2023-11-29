#!/usr/bin/python
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

ip = '192.168.33.129'
ports = (1,1024)
flags = 'A'

ans, unans = sr(IP(dst=ip)/TCP(dport=ports, flags=flags),
         retry=1, timeout=1, threaded=True, verbose=0)

tcp_ans = ans.filter(lambda s, r: r.haslayer(TCP))

r_ans = tcp_ans.filter(lambda s, r: r[TCP].flags.R)
           
icmp_ans = ans.filter(lambda s,r: r.haslayer(ICMP))
unreachable_ans = icmp_ans.filter(
    lambda s, r: r[ICMP].type == 3 and
                 int(r[ICMP].code) in [1, 2, 3, 9, 10, 13]
)

open_ans = []
closed_ans = []
filtered_ans = unans + unreachable_ans
unfiltered_ans = r_ans

print('open:', len(open_ans))
print('closed:', len(closed_ans))
print('filtered:', len(filtered_ans),
      '(unanswered:', len(unans), 'unreachable:', len(unreachable_ans), ')')
print('unfiletered:', len(unfiltered_ans))

print('port\tstatus\tservice')
unfiltered_ans.summary(
    lambda s, r: r.sprintf('%r,TCP.sport%\tunfiltered\t%TCP.sport%')
)

