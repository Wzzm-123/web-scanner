import requests
import logging
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("scanner.log", encoding="utf-8")
    ]
)

# 常用的反射型XSS检测Payload
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>"
]

def is_target_allowed(url):
    """目标白名单校验，防止滥用"""
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    if hostname in ("localhost", "127.0.0.1", "testphp.vulnweb.com"):
        return True
    try:
        import ipaddress
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback:
            return True
    except ValueError:
        pass
    return False

def check_xss(base_url, param_name):
    """
    检测GET参数是否存在反射型XSS。
    返回字典：{"has_xss": bool, "payload": str, "evidence": str}
    """
    if not is_target_allowed(base_url):
        logging.error("目标不在授权白名单中，拒绝执行")
        return {"has_xss": False, "payload": "", "evidence": ""}

    # 发送正常请求，确保目标可访问
    try:
        normal_resp = requests.get(base_url, timeout=5)
        if not normal_resp or not normal_resp.text:
            return {"has_xss": False, "payload": "", "evidence": ""}
    except Exception as e:
        logging.debug(f"请求失败: {e}")
        return {"has_xss": False, "payload": "", "evidence": ""}

    # 逐个尝试XSS payload
    for payload in XSS_PAYLOADS:
        # 使用urllib正确构造带payload的URL
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]   # 替换参数值
        new_query = urlencode(params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()

        try:
            resp = requests.get(test_url, timeout=5)
            if not resp or not resp.text:
                continue
            # 核心检测：payload是否原样出现在响应中（未做HTML编码）
            if payload in resp.text:
                evidence = resp.text[:200]  # 截取前200字符作为证据
                logging.info(f"检测到反射型XSS，参数:{param_name}, payload:{payload}")
                return {"has_xss": True, "payload": payload, "evidence": evidence}
        except Exception as e:
            logging.debug(f"请求失败: {e}")

    return {"has_xss": False, "payload": "", "evidence": ""}