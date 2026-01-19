import socket
import time
import re
from core.protocols.base import BaseProtocol

class TelnetProtocol(BaseProtocol):
    def handle(self, s):
        """Telnet 전용 스마트 협상 로직"""
        # print(f"[DEBUG] TelnetProtocol 시작 (Port {self.port})")
        s.settimeout(1.0)
        total_data = b""
        max_loops = 5

        for i in range(max_loops):
            try:
                chunk = s.recv(4096)
                if not chunk: break
                
                # 키워드 발견 시 즉시 종료 (빠른 응답)
                if b"login:" in chunk or b"Ubuntu" in chunk or b"Metasploitable" in chunk:
                    total_data += chunk
                    break
                
                # 협상 패킷 처리 (거절 패킷 전송)
                if b'\xff' in chunk:
                    reply = self._build_rejection(chunk)
                    if reply:
                        s.send(reply)
                        time.sleep(0.5)
                        continue
                
                total_data += chunk
                
            except socket.timeout:
                s.send(b"\r\n") # 타임아웃 시 엔터 전송
                continue
            except Exception:
                break
        
        return total_data

    def _build_rejection(self, chunk):
        """거절 패킷 생성 헬퍼 함수"""
        reply = b""
        idx = 0
        while idx < len(chunk):
            if chunk[idx] == 0xff:
                if idx + 2 < len(chunk):
                    cmd = chunk[idx+1]
                    opt = chunk[idx+2]
                    # DO(fd) -> WONT(fc), WILL(fb) -> DONT(fe)
                    if cmd == 0xfd: reply += b'\xff\xfc' + bytes([opt])
                    elif cmd == 0xfb: reply += b'\xff\xfe' + bytes([opt])
                    idx += 3
                else: idx += 1
            else: idx += 1
        return reply

    def parse(self, data):
        """
        Telnet 파싱 로직 (ASCII Art 필터링 포함)
        """
        if not data: return None
        try:
            # 1. 협상 코드 제거
            cleaned = re.sub(b'\xff\xfa.*?\xff\xf0', b'', data, flags=re.DOTALL)
            cleaned = re.sub(b'\xff[\xfb-\xfe].', b'', cleaned)
            cleaned = re.sub(b'\xff[\xf0-\xfa]', b'', cleaned)
            
            # 2. 디코딩 및 라인 분리
            text = cleaned.decode('utf-8', errors='ignore')
            lines = text.split('\n')
            
            collected_info = []

            # 3. 의미 있는 줄 찾기
            for line in lines:
                line = line.strip()
                if not line: continue 
                
                # ASCII Art(그림) 거르기 (특수문자 비율 확인)
                special_chars = len(re.findall(r'[_|\\/]', line))
                alnum_chars = len(re.findall(r'[a-zA-Z0-9]', line))
                if special_chars > alnum_chars:
                    continue

                # 핵심 정보 수집
                if "login:" in line:
                    collected_info.append(line)
                elif "Ubuntu" in line or "Linux" in line or "Metasploitable" in line:
                    collected_info.append(line)
                elif re.search(r'\d+\.\d+\.\d+', line): # 커널 버전 등
                    collected_info.append(line)

            if collected_info:
                # 중복 제거 후 합치기
                unique_info = list(dict.fromkeys(collected_info))
                return f"Telnet ({' | '.join(unique_info)})"
            
            # 아무것도 못 찾았으면 마지막 줄 리턴
            for line in reversed(lines):
                line = line.strip()
                if len(line) > 2 and not line.startswith('_'): 
                    return f"Telnet ({line})"
            
            return "Telnet (Unknown Banner)"
        except: 
            return "Telnet (Parse Error)"