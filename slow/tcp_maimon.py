from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

targets = '127.0.0.1'
ports = 80
#ports = (1,100)
#ports = [80, 8080]

def test_port(ip: str, port: int) -> str:
    ans = sr1(IP(dst=ip)/TCP(dport=port, flags='FA'),
              retry=1, timeout=1, threaded=True)
    if not ans:
        return "open|filtered"
    elif ans.haslayer(TCP):
        flags = ans.getlayer(TCP).flags
        if flags.R:
            return "closed"
    elif ans.haslayer(ICMP):
        icmp_type = ans.getlayer(ICMP).type
        icmp_code = int(ans.getlayer(ICMP).code)
        if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
            return "filetered"

for target in targets:
    for port in ports:
        ans = test_port(ip=target, port=port)
        print(f'{target}:{port} is {ans}')
