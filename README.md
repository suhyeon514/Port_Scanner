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
│   ├── analyzer_1.py
│   ├── scanner.py
│   ├── protocols/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── dns.py
│   │   └── telnet.py
│   └── scan_types/
│       ├── __init__.py
│       ├── base.py
│       ├── connect.py
│       └── syn.py
└── utils/
        ├── __init__.py
        ├── config_loader.py
        ├── logger.py
        └── validator.py
```

## 설정 파일(config/settings.yaml) 예시 및 설명

```yaml
# config/settings.yaml 예시
target:
    ip: "192.168.116.137"        # 단일 IP 또는 대역 (CIDR)
    ports: "22, 3306, 445, 23, 80, 53, 21, 25" # 범위 및 특정 포트 혼용 가능

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
    filename: "scan_result.log"
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
- **logging.filename**: 로그 파일명

---
프로젝트 사용 및 설정에 대한 자세한 내용은 각 소스 파일의 주석과 예시를 참고해 주세요.

사용법, 구조, 설정 방법 등 프로젝트 설명을 여기에 작성하세요.


## 폴더 및 파일별 설명

- **main.py**: 프로그램 실행 진입점. 전체 스캐너를 구동하는 메인 스크립트입니다.
- **README.md**: 프로젝트 설명서.
- **requirements.txt**: 필요한 파이썬 패키지 목록.

### config/
- **settings.yaml**: 스캐너 동작을 제어하는 환경설정 파일.

### core/
- **__init__.py**: core 모듈 패키지 초기화 파일.
- **analyzer.py**: 스캔 결과 분석 및 처리 로직.
- **analyzer_1.py**: 추가/실험적 분석 기능(사용자 정의 또는 확장용).
- **scanner.py**: 실제 포트 스캔 로직의 핵심 구현.
  
#### core/protocols/
- **base.py**: 프로토콜 처리의 기본 클래스 및 공통 로직.
- **dns.py**: DNS 프로토콜 관련 스캔 및 분석 기능.
- **telnet.py**: Telnet 프로토콜 관련 스캔 및 분석 기능.

#### core/scan_types/
- **base.py**: 스캔 방식의 기본 클래스 및 공통 로직.
- **connect.py**: Connect 스캔 방식 구현.
- **syn.py**: SYN(stealth) 스캔 방식 구현.

### utils/
- **config_loader.py**: 설정 파일 로딩 및 파싱 유틸리티.
- **logger.py**: 로그 기록 및 관리 유틸리티.
- **validator.py**: 입력값 및 설정값 검증 유틸리티.

---
각 파일의 상세한 사용법과 예시는 소스 코드 내 주석을 참고해 주세요.


