# core/protocols/base.py
class BaseProtocol:
    def __init__(self, port, timeout):
        self.port = port
        self.timeout = timeout

    def send_probe(self, socket):
        """서버에 먼저 보낼 데이터가 있다면 구현 (예: HTTP GET)"""
        pass

    def handle(self, socket):
        """소켓 통신을 수행하고 배너 문자열을 리턴"""
        # 기본 동작: 그냥 받기
        return socket.recv(4096)

    def parse(self, data):
        """받은 데이터를 해석해서 버전 정보 리턴"""
        # 기본 동작: 디코딩만
        try:
            return data.decode('utf-8').strip()
        except:
            return str(data)