# PortScanner

네트워크 포트 스캐너 프로젝트입니다. 다양한 스캔 방식과 프로토콜을 지원하며, 설정 파일을 통해 손쉽게 환경을 구성할 수 있습니다.

## 폴더 구조

```
PortScanner/
├── main.py
├── README.md
├── requirements.txt
├── config/
│   └── settings.yaml
├── core/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── scanner.py
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── dns.py
│   │   ├── http.py
│   │   ├── smb.py
│   │   ├── ssh.py
│   │   └── telnet.py
│   └── scan_types/
│       ├── __init__.py
│       ├── base.py
│       ├── connect.py
│       └── syn.py
├── utils/
│   ├── __init__.py
│   ├── config_loader.py
│   ├── logger.py
│   └── validator.py
└── logs/
    ├── application.log
```

## 설정 파일(config/settings.yaml) 예시 및 설명

```yaml
# config/settings.yaml 예시
target:
  ip: "192.168.116.137"        # 단일 IP 또는 대역 (CIDR)
  ports: "22, 3306, 445, 23, 80, 53, 21, 25, 1-500" # 범위 및 특정 포트 혼용 가능

scan_options:
    mode: "CONNECT"           # 스캔 모드: SYN (Stealth), CONNECT (Basic), FIN
    timeout: 1.5              # 패킷 응답 대기 시간 (초)
    randomize_order: true     # 포트 스캔 순서 랜덤화 (방화벽 우회용)
    timing_jitter:            # 패킷 전송 간격 (초) - 탐지 회피
        min: 0.1
        max: 0.5

advanced:
    service_detection: true   # 비표준 포트 및 서비스 버전 탐지 여부 (Phase 3 기능)
    decoy_ip:                 # 미끼 IP (Phase 4 기능 - 옵션)
        - "10.0.0.1"
        - "10.0.0.2"

logging:
  level: "INFO"             # DEBUG, INFO, WARNING, ERROR
  save_file: true
  console_output: "open_only" # "open_only", "all", "none" 중 선택 가능
```

### 설정 항목 설명
- **target.ip**: 스캔할 대상 IP 주소 또는 대역(CIDR 지원)
- **target.ports**: 스캔할 포트 번호(쉼표로 구분, 범위 및 특정 포트 혼용 가능)
- **scan_options.mode**: 스캔 방식 (CONNECT, SYN, FIN)
- **scan_options.timeout**: 포트 응답 대기 시간(초)
- **scan_options.randomize_order**: 포트 스캔 순서 랜덤화 여부
- **scan_options.timing_jitter.min/max**: 패킷 전송 간격 랜덤 범위(탐지 회피)
- **advanced.service_detection**: 서비스 버전 탐지 활성화 여부
- **advanced.decoy_ip**: 미끼 IP 리스트(옵션)
- **logging.level**: 로그 레벨 (DEBUG, INFO, WARNING, ERROR)
- **logging.save_file**: 로그 파일 저장 여부
- **logging.console_output**: 콘솔 출력 옵션 (`open_only`, `all`, `none`)

---

## 주요 기능

1. **스캔 방식**:
   - SYN 스캔: TCP SYN 패킷을 사용해 포트 상태를 분석합니다.
   - CONNECT 스캔: TCP 3-Way Handshake를 통해 포트 상태를 확인합니다.
   => 추후 방법이 더 추가될 수 있습니다

2. **프로토콜 분석**:
   - DNS, HTTP, SMB 등 특정 프로토콜에 대해 배너 정보를 분석합니다.

3. **설정 기반 동작**:
   - YAML 설정 파일을 통해 스캔 대상, 모드, 타임아웃, 로그 옵션 등을 제어할 수 있습니다.

---


프로젝트 사용 및 설정에 대한 자세한 내용은 각 소스 파일의 주석과 예시를 참고해 주세요.

사용법, 구조, 설정 방법 등 프로젝트 설명을 여기에 작성하세요.


## 폴더 및 파일별 설명

- **main.py**: 프로그램 실행 진입점. 전체 스캐너를 구동하는 메인 스크립트
- **README.md**: 프로젝트 설명서.
- **requirements.txt**: 필요한 파이썬 패키지 목록.

### config/
- **settings.yaml**: 스캐너 동작을 제어하는 환경설정 파일.

### core/
- **__init__.py**: core 모듈 패키지 초기화 파일.
- **analyzer.py**: 스캔 결과 분석 및 처리 로직.
- **scanner.py**: 실제 포트 스캔 로직의 핵심 구현.
  
#### core/protocols/
- **base.py**: 프로토콜 처리의 기본 클래스 및 공통 로직.
- **dns.py**: DNS 프로토콜 관련 스캔 및 분석 기능.
- **http.py**: HTTP 프로토콜 관련 스캔 및 분석 기능.
- **smb.py**: SMB 프로토콜 관련 스캔 및 분석 기능.
- **ssh.py**: SSH 프로토콜 관련 스캔 및 분석 기능.
- **telnet.py**: Telnet 프로토콜 관련 스캔 및 분석 기능.

#### core/scan_types/
- **base.py**: 스캔 방식의 기본 클래스 및 공통 로직.
- **connect.py**: Connect 스캔 방식 구현.
- **syn.py**: SYN(stealth) 스캔 방식 구현.

#### utils/
- **config_loader.py**: 설정 파일(`settings.yaml`)을 로드하고 값을 가져오는 유틸리티.
- **logger.py**: 중앙화된 로깅 설정을 제공하며, 모든 로그를 `logs/application.log`에 기록
- **validator.py**: 입력값 검증 로직을 포함

#### logs/
- 스캔 및 디버깅 로그가 저장되는 디렉토리. 기본적으로 `logs/application.log`에 모든 로그가 기록





## 실행 방법

1. Python 환경 설정:
   ```bash
   pip install -r requirements.txt
   ```

2. 설정 파일 수정:
   - `config/settings.yaml` 파일을 열어 스캔할 IP, 포트, 옵션 등을 설정합니다.

3. 프로그램 실행:
   ```bash
   python main.py
   ```

4. 결과 확인:
   - 스캔 결과는 콘솔에 출력되며, 로그는 `logs/application.log` 파일에 저장됩니다.

---

## 코드 운영 방식

### 1. 전체 실행 흐름

```
main.py
  │
  ├─ ConfigLoader.load_config()        # YAML 설정 파일 읽기
  │
  └─ PortScanner(config).run()         # 스캐너 실행
       │
       ├─ _get_scanner_engine()        # 모드에 따라 스캔 엔진 선택 (Factory)
       │     ├─ SynScanner             # SYN 모드
       │     └─ ConnectScanner         # CONNECT 모드
       │
       ├─ _parse_ports()               # 포트 문자열 파싱 (범위/개별 혼용)
       │
       └─ [포트 반복]
             ├─ scanner_engine.scan()  # 포트 상태 확인 ("Open" / "Closed" / "Filtered")
             └─ ServiceDetector.get_banner()  # Open 포트의 서비스 정보 분석 (선택)
                   ├─ 프로토콜별 전담 핸들러 (port → handler 매핑)
                   │     ├─ SshProtocol (22)
                   │     ├─ TelnetProtocol (23)
                   │     ├─ DnsProtocol (53)
                   │     ├─ HttpProtocol (80, 8080)
                   │     └─ SmbProtocol (445)
                   └─ 일반 배너 그래빙 (그 외 포트)
```

---

### 2. 적용된 디자인 패턴

#### ① Factory 패턴 — 스캔 엔진 선택
`PortScanner._get_scanner_engine()`은 설정 파일의 `scan_options.mode` 값을 읽어,
적합한 스캔 클래스 인스턴스를 생성하고 반환합니다.
`PortScanner`는 구체적인 패킷 조작 방식을 몰라도 되며, 새 스캔 방식을 추가할 때 이 메서드만 수정하면 됩니다.

```python
# core/scanner.py
def _get_scanner_engine(self):
    if self.scan_mode == 'SYN':
        return SynScanner(timeout=self.timeout)
    elif self.scan_mode == 'CONNECT':
        return ConnectScanner(timeout=self.timeout)
    else:
        return SynScanner(timeout=self.timeout)  # 기본값
```

#### ② Strategy 패턴 — 스캔 방식 교체 가능
`BaseScanner` 추상 클래스를 통해 스캔 방식을 인터페이스로 정의합니다.
`SynScanner`와 `ConnectScanner`는 각각 동일한 `scan(target_ip, port, src_port)` 인터페이스를 구현하며,
`PortScanner`는 어떤 엔진이 선택되었는지와 무관하게 동일한 방식으로 호출합니다.

```
BaseScanner (추상)
  ├─ SynScanner    → Scapy를 이용한 TCP SYN 패킷 전송
  └─ ConnectScanner → Python socket으로 3-Way Handshake
```

#### ③ Template Method 패턴 — 프로토콜 핸들러
`BaseProtocol`은 `handle()` (통신 수행)과 `parse()` (데이터 해석)의 뼈대를 정의합니다.
각 프로토콜 클래스는 이 두 메서드를 오버라이드해 프로토콜별 고유 로직을 구현합니다.

```
BaseProtocol
  ├─ handle(socket) → 서버와 통신해 원시 데이터 반환
  └─ parse(data)    → 원시 데이터에서 버전·서비스 정보 추출

  구현체:
  ├─ SshProtocol    → Paramiko Transport로 알고리즘·인증 방식까지 수집
  ├─ TelnetProtocol → 협상 패킷 처리 및 배너 텍스트 정제
  ├─ DnsProtocol    → TCP DNS version.bind 쿼리 전송·파싱
  ├─ HttpProtocol   → HTTP GET 요청 후 Server 헤더·Title 추출
  └─ SmbProtocol    → SMB Negotiate 패킷 전송 후 버전 문자열 추출
```

#### ④ 의존성 주입 (Dependency Injection)
`PortScanner`는 생성자에서 `config` 딕셔너리를 주입받아 동작합니다.
설정값에 따라 스캔 엔진, 타임아웃, 지터, 서비스 탐지 여부 등을 결정하므로,
외부에서 `config`만 교체하면 동작 방식 전체를 변경할 수 있습니다.

---

### 3. 모듈 간 의존 관계

```
main.py
  ├── utils/config_loader.py   (설정 로드)
  └── core/scanner.py
        ├── utils/validator.py           (IP·포트 유효성 검사)
        ├── core/scan_types/syn.py       (SYN 스캔)
        ├── core/scan_types/connect.py   (Connect 스캔)
        └── core/analyzer.py
              ├── utils/logger.py        (공통 로거)
              └── core/protocols/
                    ├── base.py
                    ├── dns.py
                    ├── http.py
                    ├── smb.py
                    ├── ssh.py
                    └── telnet.py
```

`utils/` 모듈은 순수 유틸리티로, 다른 모듈에 의존하지 않습니다.
`core/protocols/`와 `core/scan_types/`는 서로 직접 의존하지 않으며,
각각 `core/analyzer.py`와 `core/scanner.py`를 통해 통합됩니다.

---

### 4. 설정 기반(Config-Driven) 운영

모든 동작은 `config/settings.yaml`에 의해 제어됩니다.
코드 수정 없이 설정 파일만 변경해 아래 항목을 조절할 수 있습니다.

| 설정 항목 | 제어 대상 |
|---|---|
| `scan_options.mode` | 사용할 스캔 엔진 (SYN / CONNECT) |
| `scan_options.timeout` | 패킷 응답 대기 시간 |
| `scan_options.randomize_order` | 포트 스캔 순서 랜덤화 |
| `scan_options.timing_jitter` | 포트 간 지연 시간 (방화벽 우회) |
| `advanced.service_detection` | 서비스 버전 탐지 활성화 여부 |
| `logging.console_output` | 콘솔 출력 범위 (open_only / all / none) |

---

### 5. 로깅 전략

`utils/logger.py`에서 `app_logger`(ApplicationLogger) 싱글턴 인스턴스를 생성하고,
모든 모듈은 이 인스턴스를 `import`해 공유합니다.
로그는 `logs/application.log`에 파일로만 기록되며, 콘솔에는 출력되지 않습니다.

```python
# 모든 모듈에서 동일한 방식으로 사용
from utils.logger import app_logger as logger

logger.debug("...")
logger.info("...")
logger.error("...")
```

---

### 6. 새 스캔 방식 추가 방법

1. `core/scan_types/` 아래 새 파일 생성 (예: `fin.py`)
2. `BaseScanner`를 상속하고 `scan(target_ip, port, src_port)` 메서드 구현
3. `core/scanner.py`의 `_get_scanner_engine()` 메서드에 분기 추가

```python
# core/scan_types/fin.py
from core.scan_types.base import BaseScanner

class FinScanner(BaseScanner):
    def scan(self, target_ip, port, src_port):
        # FIN 패킷 전송 로직 구현
        ...
```

### 7. 새 프로토콜 핸들러 추가 방법

1. `core/protocols/` 아래 새 파일 생성 (예: `ftp.py`)
2. `BaseProtocol`을 상속하고 `handle(socket)` 및 `parse(data)` 메서드 구현
3. `core/analyzer.py`의 `ServiceDetector.protocol_map`에 포트 번호와 함께 등록

```python
# core/protocols/ftp.py
from core.protocols.base import BaseProtocol

class FtpProtocol(BaseProtocol):
    def handle(self, sock):
        return sock.recv(4096)  # FTP 서버는 먼저 배너를 보냄

    def parse(self, data):
        ...
```
