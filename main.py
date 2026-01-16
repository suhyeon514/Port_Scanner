# [진입점] 프로그램 실행 파일
from utils.config_loader import ConfigLoader
from core.scanner import PortScanner
# from utils.logger import setup_logger # 나중에 구현

def main():
    # 1. 설정 로드
    print("[*] 설정을 불러오는 중...")
    loader = ConfigLoader()
    try:
        config = loader.load_config()
    except Exception as e:
        print(f"[!] 설정 로드 실패: {e}")
        return

    # 2. 설정 변수 추출
    target_ip = config['target']['ip']
    scan_mode = config['scan_options']['mode']
    
    print(f"[*] 스캔 시작 -> 대상: {target_ip}, 모드: {scan_mode}")

    # 3. 스캐너 객체 생성 및 실행 (의존성 주입)
    scanner = PortScanner(config)
    scanner.run()

    print("[*] 스캔이 완료되었습니다.")

if __name__ == "__main__":
    main()