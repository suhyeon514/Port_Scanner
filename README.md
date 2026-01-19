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
    ├── analyzer_log.json
    ├── analyzer_log.txt
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
- **logger.py**: 중앙화된 로깅 설정을 제공하며, 모든 로그를 `logs/application.log`에 기록합니다.
- **validator.py**: 입력값 검증 로직을 포함합니다.

#### logs/
- 스캔 및 디버깅 로그가 저장되는 디렉토리입니다. 기본적으로 `logs/application.log`에 모든 로그가 기록됩니다.





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
