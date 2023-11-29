#!/usr/bin/python
from scapy.layers.inet import IP, UDP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

ip = '192.168.33.129'
ports = (1,1024)

ans, unans = sr(IP(dst=ip)/UDP(dport=ports),
         retry=1, timeout=1, threaded=True, verbose=0)

udp_ans = ans.filter(lambda s, r: r.haslayer(UDP))

icmp_ans = ans.filter(lambda s,r: r.haslayer(ICMP))
code3_ans = icmp_ans.filter(
    lambda s, r: r[ICMP].type == 3 and int(r[ICMP].code) == 3
)
unreachable_ans = icmp_ans.filter(
    lambda s, r: r[ICMP].type == 3 and
                 int(r[ICMP].code) in [1, 2, 9, 10, 13]
)

open_ans = udp_ans
open_filtered_ans = unans
closed_ans = code3_ans
filtered_ans = unreachable_ans
unfiltered_ans = []

print('open|filtered:', len(open_filtered_ans))
print('closed:', len(closed_ans))
print('filtered:', len(filtered_ans),
      '(unreachable:', len(unreachable_ans), ')')
print('unfiletered:', len(unfiltered_ans))

print('port\tstatus\tservice')
open_ans.summary(
    lambda s, r: r.sprintf('%r,UDP.sport%\topen\tUDP.dport%')
)
open_filtered_ans.filter(
    lambda s: s.sprintf('%r,UDP.dport%') != s.sprintf('%UDP.dport%')
).summary(
    lambda s: s.sprintf('%r,UDP.dport%\topen|filtered\t%UDP.dport%')
)
