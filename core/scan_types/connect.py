# 관리자 권한을 얻을 수 없는 환경에서 스캔해야 할 때.

# Scapy 설치가 불가능하거나 라이브러리 의존성을 줄이고 싶을 때.

# IPv6 등 복잡한 네트워크 환경에서 OS의 안정적인 네트워크 스택에 의존하고 싶을 때.
import socket
from core.scan_types.base import BaseScanner

class ConnectScanner(BaseScanner):
    def scan(self, target_ip, port, src_port):
        """
        Python의 Native Socket을 이용한 TCP Connect 스캔
        3-Way Handshake를 완전히 맺습니다.
        """
        # 1. 소켓 객체 생성 (IPv4, TCP)
        conn_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. 타임아웃 설정 (너무 오래 기다리지 않도록)
        conn_skt.settimeout(self.timeout)
        
        try:
            # [참고] Connect 스캔은 OS가 소스 포트를 자동 할당하는 것이 일반적입니다.
            # 굳이 src_port를 지정하려면 bind()를 써야 하지만, 
            # 포트 충돌(Address already in use)이 자주 발생하므로 생략하는 것이 더 안정적입니다.
            # conn_skt.bind(('', src_port)) 
            
            # 3. 연결 시도 (3-Way Handshake 시작)
            # connect()는 성공하면 None을 반환, 실패하면 예외(Exception)를 발생시킵니다.
            conn_skt.connect((target_ip, port))
            
            # 4. 여기까지 코드가 도달했다면 연결 성공 (Open)
            conn_skt.close() # 예의 바르게 연결 끊기
            return "Open"
            
        except socket.timeout:
            # 응답이 없어서 타임아웃 발생 -> 방화벽 차단 가능성
            return "Filtered"
            
        except ConnectionRefusedError:
            # 서버가 RST 패킷을 보내 거절함 -> 닫힌 포트
            return "Closed"
            
        except Exception as e:
            # 그 외 네트워크 에러
            return "Filtered"
            
        finally:
            # 소켓 자원 반납 (매우 중요!)
            conn_skt.close()