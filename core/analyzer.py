import socket
import re
import ssl
import logging
from utils.logger import app_logger as logger

from core.protocols.telnet import TelnetProtocol
from core.protocols.base import BaseProtocol
from core.protocols.dns import DnsProtocol
from core.protocols.smb import SmbProtocol
from core.protocols.http import HttpProtocol
from core.protocols.ssh import SshProtocol

# logger = setup_logger(__name__)
# logger = setup_logger(name="ConfigLoader", log_file="logs/analyzer.log", level=logging.DEBUG)


class ServiceDetector:
    def __init__(self):
        logger.debug("Initializing ServiceDetector")
        # 정규식 패턴 (기존 유지)
        self.signatures = [
            # ('SSH', re.compile(r'SSH-([\d.]+)-([^\r\n]+)', re.IGNORECASE)),
            ('HTTP', re.compile(r'Server:\s*([^\r\n]+)', re.IGNORECASE)),
            ('SMTP', re.compile(r'220\s+([-\.\w\d\s]+)\s+ESMTP', re.IGNORECASE)),
            ('FTP', re.compile(r'220\s+([-\.\w\d\s()]+)', re.IGNORECASE)),
            ('MySQL', re.compile(r'(\d\.\d\.\d+[\w\-.+]*)', re.IGNORECASE)), 
            ('POP3', re.compile(r'\+OK\s+(.*)', re.IGNORECASE)),
        ]

        # Probes (기존 유지)
        self.probes = {
            # 80: b"GET / HTTP/1.0\r\n\r\n",
            # 8080: b"GET / HTTP/1.0\r\n\r\n",
        }

        # 프로토콜 핸들러 매핑
        self.protocol_map = {
            # 21: FtpProtocol,    # (FTP도 나중에 만드시겠죠?)
            22: SshProtocol,    # [NEW] 22번 포트도 전문가에게 위임!
            23: TelnetProtocol,
            # 25: SmtpProtocol,   # (SMTP도 같은 방식 가능)
            53: DnsProtocol,
            80: HttpProtocol,   # [NEW] 80번은 HTTP 전문가에게!
            8080: HttpProtocol, # 8080번도 HTTP 전문가에게!
            445: SmbProtocol,
        }

    def get_banner(self, ip, port, timeout=2):
        logger.debug(f"Starting banner detection for IP: {ip}, Port: {port}, Timeout: {timeout}")
        try:
            # 1. SSL/TLS 확인 (HTTPS)
            if port in [443, 8443]:
                logger.debug("Checking for SSL/TLS on port 443 or 8443")
                cert_info = self._get_ssl_info(ip, port, timeout)
                if cert_info:
                    logger.debug(f"SSL/TLS info detected: {cert_info}")
                    return cert_info

            # 2. 소켓 생성
            logger.debug("Creating socket connection")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if port == 445:
                s.settimeout(timeout + 2.0)
            else:
                s.settimeout(timeout)
            
            logger.debug(f"Connecting to {ip}:{port}")
            s.connect((ip, port))
            
            # =========================================================
            # [CASE A] 전담 프로토콜 핸들러가 있는 경우 (예: Telnet)
            # =========================================================
            if port in self.protocol_map:
                logger.debug(f"Using protocol handler for port {port}")
                handler_class = self.protocol_map[port]
                handler = handler_class(port, timeout)
                
                # 위임: 통신 수행
                logger.debug("Delegating communication to protocol handler")
                raw_data = handler.handle(s)
                s.close()
                
                # 위임: 데이터 해석
                logger.debug("Parsing data using protocol handler")
                parsed_data = handler.parse(raw_data)
                logger.info(f"Protocol {handler_class.__name__} detected: {parsed_data}")
                return parsed_data
            
            # =========================================================
            # [CASE B] 일반적인 포트 (FTP, SSH, HTTP 등)
            # =========================================================
            else:
                logger.debug(f"No specific protocol handler for port {port}, using generic probe")
                # 1. Active Probe 전송 (HTTP, SMB 등 말을 먼저 걸어야 하는 경우)
                if port in self.probes:
                    logger.debug(f"Sending probe for port {port}")
                    s.send(self.probes[port])

                # 2. 데이터 수신
                logger.debug("Receiving data from socket")
                banner_bytes = s.recv(4096)
                s.close()

                # 3. 기존 분석 로직 재사용 (_analyze_generic 대신 기존 메서드 활용)
                logger.debug("Cleaning and analyzing received data")
                banner_str = self._clean_binary(banner_bytes)
                analyzed_data = self._analyze(banner_str, port)
                logger.info(f"Generic protocol detected: {analyzed_data}")
                return analyzed_data

        except Exception as e:
            logger.error(f"Error during banner detection: {e}")
            return f"Unknown ({str(e)})"

    # ---------------------------------------------------------
    # 기존 헬퍼 메서드들 (이전 코드 복구)
    # ---------------------------------------------------------
    def _get_ssl_info(self, ip, port, timeout):
        logger.debug(f"Attempting to retrieve SSL/TLS info for {ip}:{port}")
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssl_info = f"HTTPS ({ssock.version()}, {ssock.cipher()[0]})"
                    logger.debug(f"SSL/TLS info: {ssl_info}")
                    return ssl_info
        except Exception as e:
            logger.error(f"Failed to retrieve SSL/TLS info: {e}")
            return None

    def _clean_binary(self, data):
        logger.debug("Cleaning binary data")
        try:
            return data.decode('utf-8')
        except Exception as e:
            logger.warning(f"Failed to decode binary data: {e}, attempting regex cleaning")
            clean = re.findall(b'[ -~]{4,}', data)
            if clean:
                return b' '.join(clean).decode('utf-8', errors='ignore')
            return str(data[:20])

    def _analyze(self, banner, port):
        logger.debug(f"Analyzing banner for port {port}")
        if not banner:
            logger.info("No banner received, port is open but no data")
            return "Open (Empty Banner)"
        banner = banner.strip()
        for service, regex in self.signatures:
            match = regex.search(banner)
            if match:
                logger.debug(f"Service match found: {service}")
                if match.groups():
                    return f"{service} ({match.group(1).strip('() 'r'n')})"
                return service
        if port == 445 and ("SMB" in banner or "Samba" in banner):
            return "SMB (Windows/Samba)"
        if port == 3306 and len(banner) > 5:
            return f"MySQL ({banner[:30]}...)"
        clean = banner.replace('\r', '').replace('\n', ' ').strip()
        logger.debug(f"Unknown service detected: {clean[:40]}...")
        return f"Unknown ({clean[:40]}...)"