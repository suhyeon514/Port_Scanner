import ipaddress
import re
import os
import json

# IP 주소 유효성 검사 함수
def is_valid_ip(ip):
    """
    IP 주소가 유효한지 확인합니다.
    :param ip: str, 검사할 IP 주소
    :return: bool, 유효하면 True, 아니면 False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# 포트 번호 유효성 검사 함수
def is_valid_port(port):
    """
    포트 번호가 유효한지 확인합니다.
    :param port: int, 검사할 포트 번호
    :return: bool, 유효하면 True, 아니면 False
    """
    return 0 <= port <= 65535

# 도메인 이름 유효성 검사 함수
def is_valid_domain(domain):
    """
    도메인 이름이 유효한지 확인합니다.
    :param domain: str, 검사할 도메인 이름
    :return: bool, 유효하면 True, 아니면 False
    """
    domain_regex = r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
    return re.match(domain_regex, domain) is not None

# 파일 경로 유효성 검사 함수
def is_valid_file_path(file_path):
    """
    파일 경로가 유효한지 확인합니다.
    :param file_path: str, 검사할 파일 경로
    :return: bool, 유효하면 True, 아니면 False
    """
    return os.path.exists(file_path) and os.path.isfile(file_path)

# JSON 파일 유효성 검사 함수
def is_valid_json(file_path):
    """
    JSON 파일이 유효한지 확인합니다.
    :param file_path: str, JSON 파일 경로
    :return: bool, 유효하면 True, 아니면 False
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            json.load(f)
        return True
    except (json.JSONDecodeError, FileNotFoundError):
        return False
