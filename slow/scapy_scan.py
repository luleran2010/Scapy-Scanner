from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr
import argparse
import sys

def test_port_udp(ip: str, port: int) -> str:
    ans = sr1(IP(dst=ip)/UDP(dport=port), retry=1, timeout=1, threaded=True)
    if not ans:
        return "open|filtered"
    elif ans.haslayer(UDP):
        return "open"
    elif ans.haslayer(ICMP):
        icmp_type = ans.getlayer(ICMP).type
        icmp_code = int(ans.getlayer(ICMP).code)
        if icmp_type == 3 and icmp_code == 3:
            return "closed"
        elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
            return "filetered"

def test_port(ip: str, port: int, scanflags: str) -> str:
    if scanflags == 'U':
        return test_port_udp(ip, port)
    flags = ''
    if scanflags == 'T':
        flags = 'S'
    elif scanflags == 'X':
        flags = 'FPU'
    elif scanflags == 'M':
        flags = 'FA'
    elif scanflags == 'W':
        flags = 'A'
    else:
        flags == scanflags

    packet: Packet = IP(dst=ip)/TCP(dport=port, flags=flags)
    ans = sr1(packet, retry=1, timeout=1, threaded=True)
    if not ans:
        if scanflags in ['A', 'S', 'T', 'W']:
            return "filtered"
        else:
            return "open|closed"
    elif ans.haslayer(TCP):
        flags = ans.getlayer(TCP).flags
        if flags.S and flags.A:
            if scanflags == 'T':
                sr(IP(dst=ip)/TCP(dport=port, flags='A'))
            sr(IP(dst=ip)/TCP(dport=port, flags='R'))
            return "open"
        elif flags.R:
            if scanflags == 'A':
                return "unfiltered"
            elif scanflags  == 'W':
                window = ans.getlayer(TCP).window
                if window == 0:
                    return "closed"
                else:
                    return "open"
            else:
                return "closed"
    elif ans.haslayer(ICMP):
        icmp_type = ans.getlayer(ICMP).type
        icmp_code = int(ans.getlayer(ICMP).code)
        if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
            return "filetered"

parser = argparse.ArgumentParser(
    prog="Scapy Scanner",
    description="Port scanner based on Scapy"
)
parser.add_argument('-s', '--scanflags', type=str, default='S')
parser.add_argument('-p', '--ports', type=str)
parser.add_argument('ip', type=str, nargs='+')
args = parser.parse_args()

scanflags: str = args.scanflags
ports_str: str = args.ports
targets = args.ip

ports = []
if ports_str.startswith('@'):
    with open(ports_str[1:], 'r') as f:
        ports = [int(i.strip()) for i in f.readlines()]
else:
    for item in ports_str.split(','):
        if '-' in item:
            start, end = item.split('-')
            ports.append(list(range(int(start), int(end))))
        else:
            ports.append(int(item))

if scanflags not in list('ASFNWXMT'):
    print('scanflags should be one of ASFNWXMT')
    sys.exit(-1)

for target in targets:
    for port in ports:
        ans = test_port(ip=target, port=port)
        print(f'{target}:{port} is {ans}')