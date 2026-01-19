import socket
import paramiko
from core.protocols.base import BaseProtocol

class SshProtocol(BaseProtocol):
    def handle(self, sock):
        """
        SSH는 배너 그래빙 뿐만 아니라, 
        Paramiko Transport를 이용해 지원하는 알고리즘과 인증 방식을 확인합니다.
        """
        result = {
            "banner": "Unknown",
            "auth_methods": [],
            "ciphers": [],
            "kex": []
        }

        try:
            # 1. 기본 배너 가져오기 (Raw Socket 이용)
            # Paramiko가 소켓을 가져가기 전에 배너를 먼저 살짝 엿볼 수도 있지만,
            # 여기서는 Paramiko Transport 내부 기능을 활용하겠습니다.
            
            # Paramiko Transport 생성 (이미 연결된 소켓 활용)
            t = paramiko.Transport(sock)
            t.local_version = 'SSH-2.0-SecurityScanner' # 우리 스캐너의 이름
            
            # 2. 핸드쉐이크 시작 (알고리즘 협상)
            try:
                t.start_client()
            except Exception as e:
                return f"SSH Error (Handshake failed: {e})"

            # 3. 정보 추출
            # (1) 배너 정보
            result['banner'] = t.remote_version

            # (2) 협상된 보안 옵션 (Security Options)
            # get_security_options()는 가능한 모든 알고리즘 목록을 줍니다.
            sec_opts = t.get_security_options()
            result['ciphers'] = sec_opts.ciphers  # 지원하는 암호화 알고리즘 목록
            result['kex'] = sec_opts.kex          # 키 교환 알고리즘 목록

            # (3) 인증 방식 확인 (Auth Methods)
            # 인증 가능한 목록을 보려면 '일부러 틀린 인증'을 시도해서 
            # 서버가 "아니, 나는 이런 방식들만 지원해"라고 에러를 뱉게 만들어야 합니다.
            try:
                # 'none' 인증을 시도하면 서버는 거절하면서 가능한 목록을 줍니다.
                t.auth_none('')
            except paramiko.BadAuthenticationType as e:
                # e.allowed_types에 서버가 허용하는 인증 방식이 담겨 있습니다.
                result['auth_methods'] = e.allowed_types
            except:
                pass

            t.close()
            
            return result

        except Exception as e:
            return f"SSH Error ({str(e)})"

    def parse(self, data):
        """
        handle에서 리턴한 딕셔너리(result)를 예쁜 문자열로 변환
        """
        if isinstance(data, str):
            return data # 에러 메시지인 경우

        try:
            banner = data.get('banner', 'Unknown')
            auth_methods = data.get('auth_methods', [])
            ciphers = data.get('ciphers', [])
            
            # 1. 버전 정보 정제
            version_str = banner
            
            # 2. 인증 방식 요약
            # 예: password가 있으면 "Password Auth Allowed" 표시
            auth_str = ", ".join(auth_methods)
            
            # 3. 취약한 알고리즘 탐지 (예시)
            weak_ciphers = [c for c in ciphers if 'arcfour' in c or '3des' in c]
            weak_warning = f" [WEAK: {','.join(weak_ciphers)}]" if weak_ciphers else ""

            return f"SSH ({version_str}) | Auth: [{auth_str}]{weak_warning}"

        except Exception as e:
            return f"SSH (Parse Error: {e})"