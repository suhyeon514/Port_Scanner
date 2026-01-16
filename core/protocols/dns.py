import socket
import struct

class DnsProtocol:
    def __init__(self, port, timeout):
        self.port = port
        self.timeout = timeout

    def handle(self, sock):
        # version.bind 쿼리용 DNS 패킷 생성 (TCP)
        # DNS 헤더 + Question: version.bind, class=CH, type=TXT
        # TCP는 2바이트 길이 prefix 필요
        qname = b'\x07version\x04bind\x00'  # version.bind
        qtype = 16  # TXT
        qclass = 3  # CH (Chaosnet)
        header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        question = qname + struct.pack('!HH', qtype, qclass)
        dns_packet = header + question
        tcp_packet = struct.pack('!H', len(dns_packet)) + dns_packet
        sock.sendall(tcp_packet)
        # TCP DNS 응답: 2바이트 길이 prefix 후 데이터
        resp_len = sock.recv(2)
        if not resp_len:
            return b''
        resp_len = struct.unpack('!H', resp_len)[0]
        data = b''
        while len(data) < resp_len:
            chunk = sock.recv(resp_len - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def parse(self, data):
        # DNS 응답에서 TXT 레코드 추출
        if not data or len(data) < 12:
            return 'DNS (No Response)'
        # DNS 헤더는 12바이트
        pos = 12
        # QNAME 스킵
        while data[pos] != 0:
            pos += 1
        pos += 5  # 0(QNAME 끝) + QTYPE(2) + QCLASS(2)
        # Answer section
        if pos + 10 > len(data):
            return 'DNS (No Answer)'
        # NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        pos += 10
        if pos >= len(data):
            return 'DNS (No TXT Record)'
        txt_len = data[pos]
        pos += 1
        txt = data[pos:pos+txt_len]
        try:
            return 'DNS Version: ' + txt.decode(errors='ignore')
        except:
            return 'DNS Version: (decode error)'