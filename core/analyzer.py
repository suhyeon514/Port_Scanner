import socket
import re
import ssl
from core.protocols.telnet import TelnetProtocol
from core.protocols.base import BaseProtocol
from core.protocols.dns import DnsProtocol


class ServiceDetector:
    def __init__(self):
        # 정규식 패턴 (기존 유지)
        self.signatures = [
            ('SSH', re.compile(r'SSH-([\d.]+)-([^\r\n]+)', re.IGNORECASE)),
            ('HTTP', re.compile(r'Server:\s*([^\r\n]+)', re.IGNORECASE)),
            ('SMTP', re.compile(r'220\s+([-\.\w\d\s]+)\s+ESMTP', re.IGNORECASE)),
            ('FTP', re.compile(r'220\s+([-\.\w\d\s()]+)', re.IGNORECASE)),
            ('MySQL', re.compile(r'(\d\.\d\.\d+[\w\-.+]*)', re.IGNORECASE)), 
            ('POP3', re.compile(r'\+OK\s+(.*)', re.IGNORECASE)),
        ]

        # Probes (기존 유지)
        self.probes = {
            80: b"GET / HTTP/1.0\r\n\r\n",
            8080: b"GET / HTTP/1.0\r\n\r\n",
            445: b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x29\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00',
        }

        # 프로토콜 핸들러 매핑
        self.protocol_map = {
            23: TelnetProtocol,
            53: DnsProtocol,  # 추가
        }

    def get_banner(self, ip, port, timeout=2):
        try:
            # 1. SSL/TLS 확인 (HTTPS)
            if port in [443, 8443]:
                cert_info = self._get_ssl_info(ip, port, timeout)
                if cert_info: return cert_info

            # 2. 소켓 생성
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if port == 445: s.settimeout(timeout + 2.0)
            else: s.settimeout(timeout)
            
            s.connect((ip, port))
            
            # =========================================================
            # [CASE A] 전담 프로토콜 핸들러가 있는 경우 (예: Telnet)
            # =========================================================
            if port in self.protocol_map:
                handler_class = self.protocol_map[port]
                handler = handler_class(port, timeout)
                
                # 위임: 통신 수행
                raw_data = handler.handle(s)
                s.close()
                
                # 위임: 데이터 해석
                return handler.parse(raw_data)
            
            # =========================================================
            # [CASE B] 일반적인 포트 (FTP, SSH, HTTP 등)
            # =========================================================
            else:
                # 1. Active Probe 전송 (HTTP, SMB 등 말을 먼저 걸어야 하는 경우)
                if port in self.probes:
                    s.send(self.probes[port])

                # 2. 데이터 수신
                banner_bytes = s.recv(4096)
                s.close()

                # 3. 기존 분석 로직 재사용 (_analyze_generic 대신 기존 메서드 활용)
                banner_str = self._clean_binary(banner_bytes)
                return self._analyze(banner_str, port)

        except Exception as e:
            return f"Unknown ({str(e)})"

    # ---------------------------------------------------------
    # 기존 헬퍼 메서드들 (이전 코드 복구)
    # ---------------------------------------------------------
    def _get_ssl_info(self, ip, port, timeout):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    return f"HTTPS ({ssock.version()}, {ssock.cipher()[0]})"
        except: return None

    def _clean_binary(self, data):
        try: return data.decode('utf-8')
        except:
            clean = re.findall(b'[ -~]{4,}', data)
            if clean: return b' '.join(clean).decode('utf-8', errors='ignore')
            return str(data[:20])

    def _analyze(self, banner, port):
        if not banner: return "Open (Empty Banner)"
        banner = banner.strip()
        for service, regex in self.signatures:
            match = regex.search(banner)
            if match:
                if match.groups(): return f"{service} ({match.group(1).strip('() 'r'n')})"
                return service
        if port == 445 and ("SMB" in banner or "Samba" in banner): return "SMB (Windows/Samba)"
        if port == 3306 and len(banner) > 5: return f"MySQL ({banner[:30]}...)"
        clean = banner.replace('\r', '').replace('\n', ' ').strip()
        return f"Unknown ({clean[:40]}...)"