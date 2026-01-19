# YAML 파일을 읽어서 파이썬 객체로 변환
import yaml
import os
from utils.logger import app_logger as logger  # Use centralized app_logger

class ConfigLoader:
    def __init__(self, config_path="config/settings.yaml"):
        self.config_path = config_path
        self._config = None

    def load_config(self):
        if not os.path.exists(self.config_path):
            logger.error(f"설정 파일을 찾을 수 없습니다: {self.config_path}")
            raise FileNotFoundError(f"설정 파일을 찾을 수 없습니다: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            try:
                self._config = yaml.safe_load(f)
                logger.info("Config loaded successfully: %s", self._config)
                return self._config
            except yaml.YAMLError as e:
                logger.error("YAML 파일 파싱 중 오류 발생: %s", e)
                raise Exception(f"YAML 파일 파싱 중 오류 발생: {e}")

    def get(self, key, default=None):
        """설정값에 안전하게 접근하기 위한 헬퍼 메소드"""
        logger.debug("Starting get method")
        logger.debug("Accessing config key: %s", key)
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                logger.debug("Current level: %s, looking for key: %s", value, k)
                if isinstance(value, dict):
                    if k in value:
                        value = value[k]
                        logger.debug("Found key '%s', value: %s", k, value)
                    else:
                        logger.debug("Key '%s' not found at current level. Returning default value.", k)
                        return default
                else:
                    logger.debug("Value is not a dictionary at key '%s'.", k)
                    return default
            logger.debug("Accessed key '%s': %s", key, value)
            return value
        except Exception as e:
            logger.error("Error accessing key '%s': %s", key, e)
            return default
        

if __name__ == "__main__":
    loader = ConfigLoader()
    config = loader.load_config()
    print("[*] Config object:", config)  # Debug print
    print("[*] Attempting to access logging.filename...")  # Debug print

    # Direct access to logging.filename for debugging
    try:
        logging_config = config["logging"]
        print("[*] Direct access to logging config:", logging_config)  # Debug print
        logging_filename = logging_config.get("filename", None)
        print("[*] Direct access to logging.filename:", logging_filename)  # Debug print
    except KeyError as e:
        print(f"[ERROR] KeyError while accessing logging.filename: {e}")

    # Using get method
    # logging_filename_via_get = config.get("logging.filename")
    logging_filename_via_get = loader.get("logging.filename")
    print("Loaded logging filename via get method:", logging_filename_via_get)


    # loader는 작성하신 클래스 인스턴스이므로 커스텀 get 메서드가 동작함
