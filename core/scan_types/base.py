from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, timeout=1.0):
        self.timeout = timeout

    @abstractmethod # 추상 함수 구현 하지 않는다. 하위 클래스에서 반드시 구현해야 한다.
    def scan(self, target_ip, port, src_port):
        """
        모든 스캔 클래스는 이 함수를 반드시 구현해야 합니다.
        :return: "Open", "Closed", "Filtered" 중 하나
        """
        pass