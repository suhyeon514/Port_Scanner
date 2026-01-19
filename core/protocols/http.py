import re
from core.protocols.base import BaseProtocol

class HttpProtocol(BaseProtocol):
    def handle(self, sock):
        """
        HTTP GET 요청 전송
        """
        # HTTP 1.1은 Host 헤더가 필수입니다. (IP라도 넣어주는 게 정석)
        # Connection: close를 명시해서 서버가 응답 후 바로 끊게 유도합니다.
        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: target\r\n"
            b"User-Agent: Mozila/5.0 (Compatible; SecurityScanner/1.0)\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        sock.sendall(request)
        
        # 데이터 수신 (HTTP는 헤더+바디가 있어서 4096보다 클 수 있음)
        # 여기서는 간단히 앞부분(헤더 포함)만 받아서 분석
        try:
            return sock.recv(8192)
        except:
            return b""

    def parse(self, data):
        """
        HTTP 응답에서 Server 헤더, Title, 상태 코드 추출
        """
        if not data:
            return "HTTP (No Response)"
            
        try:
            text = data.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')
            
            # 1. 상태 코드 (첫 줄) 예: HTTP/1.1 200 OK
            status_line = lines[0] if lines else "Unknown"
            status_code = "Unknown"
            if " " in status_line:
                parts = status_line.split(" ")
                if len(parts) > 1:
                    status_code = parts[1] # 200, 404 등

            # 2. Server 헤더 찾기
            server_info = "Unknown Server"
            for line in lines:
                if line.lower().startswith("server:"):
                    server_info = line.split(":", 1)[1].strip()
                    break
            
            # 3. HTML Title 태그 찾기 (간단한 정규식)
            title = "No Title"
            title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()[:30] # 너무 길면 자름

            # 결과 조합
            return f"HTTP ({server_info} | Status: {status_code} | Title: {title})"

        except Exception as e:
            return f"HTTP (Parse Error: {e})"