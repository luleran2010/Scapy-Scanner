from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

targets = ['192.168.33.129']
ports = range(1,1024)
#ports = (1,100)
#ports = [80, 8080]

def test_port(ip: str, port: int) -> str:
    ans = sr1(IP(dst=ip)/TCP(dport=port, flags='S'),
              retry=1, timeout=1, threaded=True, verbose=0)
    if not ans:
        return "filtered"
    elif ans.haslayer(TCP):
        flags = ans.getlayer(TCP).flags
        if flags.S and flags.A:
            sr(IP(dst=ip)/TCP(dport=port, flags='R'), timeout=1, verbose=0)
            return "open"
        elif flags.R:
            return "closed"
    elif ans.haslayer(ICMP):
        icmp_type = ans.getlayer(ICMP).type
        icmp_code = int(ans.getlayer(ICMP).code)
        if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
            return "filetered"

for target in targets:
    for port in ports:
        ans = test_port(ip=target, port=port)
        if ans == "open":
            print(f'{target}:{port} is {ans}')
