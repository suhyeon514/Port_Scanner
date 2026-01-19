import time
import random
from core.analyzer import ServiceDetector
from utils.validator import is_valid_ip, is_valid_port

# [변경] 스캔 타입 모듈들 가져오기
from core.scan_types.syn import SynScanner
from core.scan_types.connect import ConnectScanner

class PortScanner:
    def __init__(self, config):
        self.config = config
        self.target_ip_str = config['target']['ip']
        self.ports_str = str(config['target']['ports'])

        # IP 주소 유효성 검사
        if not is_valid_ip(self.target_ip_str):
            raise ValueError(f"유효하지 않은 IP 주소입니다: {self.target_ip_str}")

        # 옵션 로드
        self.timeout = config['scan_options'].get('timeout', 1.0)
        self.scan_mode = config['scan_options'].get('mode', 'SYN')

        self.randomize = config['scan_options'].get('randomize_order', False)
        self.jitter_min = config['scan_options']['timing_jitter'].get('min', 0)
        self.jitter_max = config['scan_options']['timing_jitter'].get('max', 0)

        self.detector = ServiceDetector()
        self.detect_service = config['advanced'].get('service_detection', False)

        # [핵심] 현재 모드에 맞는 스캐너 인스턴스 준비 (Factory 패턴)
        self.scanner_engine = self._get_scanner_engine()

    def _get_scanner_engine(self):
        """설정된 모드에 맞는 스캔 클래스를 반환"""
        if self.scan_mode == 'SYN':
            return SynScanner(timeout=self.timeout)
        elif self.scan_mode == 'CONNECT': # [추가됨] 주석 해제 및 구현
            return ConnectScanner(timeout=self.timeout)
        else:
            print(f"[!] 경고: 지원하지 않는 모드입니다({self.scan_mode}). SYN 모드로 대체합니다.")
            return SynScanner(timeout=self.timeout)

    def _parse_ports(self, ports_str):
        # (기존 코드 유지)
        target_ports = set()
        parts = ports_str.split(',')
        for part in parts:
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                if not (is_valid_port(start) and is_valid_port(end)):
                    print(f"[!] 유효하지 않은 포트 범위: {part}")
                    continue
                target_ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not is_valid_port(port):
                    print(f"[!] 유효하지 않은 포트 번호: {port}")
                    continue
                target_ports.add(port)
        return list(target_ports)

    def run(self):
        # 색상 코드
        GREEN = "\033[92m"  # Open
        YELLOW = "\033[93m"  # Filtered
        RED = "\033[91m"  # Closed
        RESET = "\033[0m"

        target_ports = self._parse_ports(self.ports_str)

        if self.randomize:
            random.shuffle(target_ports)

        print(f"[*] Target: {self.target_ip_str}, Mode: {self.scan_mode}")
        print("-" * 60)
        print(f"{'PORT':<10} {'STATUS':<20} {'SERVICE'}")
        print("-" * 60)

        # 콘솔 출력 설정 로드
        console_output = self.config['logging'].get('console_output', 'all')

        for port in target_ports:
            # 1. Jitter (지연 시간) 적용
            if self.jitter_max > 0:
                time.sleep(random.uniform(self.jitter_min, self.jitter_max))

            # 2. 소스 포트 랜덤 생성 (공통 기능은 여기서 처리)
            src_port = random.randint(1024, 65535)

            # [핵심 변경] 선택된 스캐너 엔진에게 스캔 위임
            # scanner.py는 구체적인 패킷 조작법을 몰라도 됨
            status = self.scanner_engine.scan(self.target_ip_str, port, src_port)

            # 3. 결과 처리 및 서비스 탐지
            service_info = "Unknown"
            if status == "Open":
                if self.detect_service:
                    print(f"    [>] Port {port} 정밀 분석 중...", end='\r')
                    service_info = self.detector.get_banner(self.target_ip_str, port)

            # 색상 적용
            if status == "Open":
                colored_status = f"{GREEN}{status}{RESET}"
            elif status == "Filtered":
                colored_status = f"{YELLOW}{status}{RESET}"
            elif status == "Closed":
                colored_status = f"{RED}{status}{RESET}"
            else:
                colored_status = status

            # 콘솔 출력 조건에 따라 출력
            if console_output == "open_only" and status != "Open":
                continue
            elif console_output == "none":
                continue

            print(f"{port:<10} {colored_status:<28} {service_info}")