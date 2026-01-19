from scapy.all import IP, TCP, sr1, send, conf
from core.scan_types.base import BaseScanner

# Scapy 설정 (Verbose 끄기)
conf.verb = 0

class SynScanner(BaseScanner):
    def scan(self, target_ip, port, src_port):
        # 1. 패킷 생성
        packet = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S")
        
        # 2. 전송 및 대기
        response = sr1(packet, timeout=self.timeout)

        # 3. 분석
        if response is None:
            return "Filtered"

        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)

            # SYN+ACK (Open)
            if tcp_layer.flags == 0x12:
                # RST 보내서 연결 끊기 (Stealth)
                rst_pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="R")
                send(rst_pkt, verbose=0)
                return "Open"

            # RST+ACK (Closed)
            elif tcp_layer.flags == 0x14:
                return "Closed"

        return "Filtered"