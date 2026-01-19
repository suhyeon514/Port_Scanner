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
        if not data or len(data) < 12:
            return 'DNS (No Response)'
            
        pos = 12
        # Question Section 스킵
        while data[pos] != 0:
            pos += 1
        pos += 5 
        
        # Answer Section
        if pos >= len(data): return 'DNS (No Answer)'

        # Name 필드 스킵 (압축 포인터 C0 xx 또는 일반 라벨)
        # BIND 응답은 보통 C0 0C (2바이트)로 오지만, 안전하게 처리하려면:
        if (data[pos] & 0xC0) == 0xC0:
            pos += 2 # 포인터인 경우 2바이트 스킵
        else:
            while data[pos] != 0: pos += 1 # 포인터가 아니면 null 만날때까지
            pos += 1
            
        # Type(2) + Class(2) + TTL(4) 스킵 = 8바이트
        pos += 8
        
        # RDLENGTH (데이터 길이) 읽기 - 2바이트 Big Endian!
        if pos + 2 > len(data): return 'DNS (Malformed)'
        rd_len = struct.unpack('!H', data[pos:pos+2])[0]
        pos += 2
        
        # 실제 TXT 데이터 읽기
        # TXT 레코드는 맨 앞에 '문자열 길이(1byte)'가 포함될 수 있음 (BIND 버전에 따라 다름)
        # 단순히 남은 데이터를 다 읽거나, rd_len 만큼 읽어서 출력 가능한 것만 필터링하는 게 안전
        try:
            txt_data = data[pos:pos+rd_len]
            # TXT 레코드 내부의 첫 바이트가 길이일 수 있으므로 제거하거나 무시
            if len(txt_data) > 0:
                # 출력 가능한 문자만 필터링 (바이너리 찌꺼기 제거)
                version = ''.join([chr(b) for b in txt_data if 32 <= b <= 126])
                return f'DNS Version: {version}'
            return 'DNS Version: (Empty)'
        except Exception:
            return 'DNS Version: (Parse Error)'