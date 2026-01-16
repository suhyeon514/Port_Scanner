# YAML 파일을 읽어서 파이썬 객체로 변환
import yaml
import os

class ConfigLoader:
    def __init__(self, config_path="config/settings.yaml"):
        self.config_path = config_path
        self._config = None

    def load_config(self):
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"설정 파일을 찾을 수 없습니다: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            try:
                self._config = yaml.safe_load(f)
                return self._config
            except yaml.YAMLError as e:
                raise Exception(f"YAML 파일 파싱 중 오류 발생: {e}")

    def get(self, key, default=None):
        """설정값에 안전하게 접근하기 위한 헬퍼 메소드"""
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default