import socket
import struct
import re
from core.protocols.base import BaseProtocol

class SmbProtocol(BaseProtocol):
    def handle(self, sock):
        """
        SMBv1/v2 Negotiate Protocol Packet 전송
        이 패킷은 서버에게 "나 이런 언어(Dialect)들을 아는데, 넌 뭐야?"라고 물어봅니다.
        """
        # SMB Negotiate Request (Multi-Protocol)
        # PC NETWORK, LANMAN, NT LM 0.12 등을 포함
        probe = (
            b'\x00\x00\x00\x85'  # NetBIOS Session Service (Length=133)
            b'\xff\x53\x4d\x42'  # SMB Header Protocol ID
            b'\x72'              # Command: Negotiate Protocol
            b'\x00\x00\x00\x00'  # Status
            b'\x18'              # Flags
            b'\x01\x28'          # Flags2
            b'\x00\x00'          # PID High
            b'\x00\x00\x00\x00\x00\x00\x00\x00' # Signature
            b'\x00\x00'          # Reserved
            b'\x00\x00'          # TID
            b'\x2f\x4b'          # PID
            b'\x00\x00'          # UID
            b'\x00\x00'          # MID
            b'\x00\x54'          # Word Count (0) + Byte Count (84)
            # Dialects
            b'\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00'
            b'\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00'
            b'\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00'
            b'\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00'
            b'\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00'
            b'\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
        )
        
        sock.sendall(probe)
        
        # 응답 수신 (충분히 크게 잡음)
        try:
            return sock.recv(1024)
        except socket.timeout:
            return b''

    def parse(self, data):
        """
        SMB 응답에서 'Unix', 'Samba', 'Version' 같은 유의미한 문자열 추출
        """
        if not data:
            return "SMB (No Response)"
        
        # 1. 간단한 버전: 바이너리 다 떼고 문자열만 건져내기
        # (Samba는 보통 평문으로 자신의 버전을 뒤에 붙여서 보냅니다)
        try:
            # 출력 가능한 ASCII 문자(4글자 이상)만 추출
            strings = re.findall(b'[ -~]{4,}', data)
            if not strings:
                return "SMB (Unknown Version)"
            
            decoded = [s.decode('utf-8', errors='ignore') for s in strings]
            
            # 필터링: 유의미한 키워드가 있는 문자열 찾기
            result = []
            for s in decoded:
                # SMB 프로토콜 자체 문자열 제외 (LANMAN 등)
                if "SMB" in s or "LANMAN" in s or "LM" in s:
                    continue
                result.append(s)
            
            # 다 합쳐서 반환 (예: Unix Samba 3.0.20-Debian)
            if result:
                return f"SMB ({', '.join(result)})"
            
            # 만약 다 걸러졌으면 원본 문자열 중 일부 반환
            full_str = ' '.join(decoded)
            return f"SMB Detected ({full_str[:40]}...)"

        except Exception as e:
            return f"SMB (Parse Error: {e})"