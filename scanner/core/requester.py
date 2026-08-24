import requests
import logging
from urllib.parse import urlparse, parse_qs, urlencode

class Requester:
    """统一HTTP请求引擎，支持会话保持、Cookie、代理"""
    
    def __init__(self, cookies=None, proxy=None, timeout=5):
        """
        :param cookies: dict 或 Cookie 字符串，如 "PHPSESSID=abc123"
        :param proxy: 代理地址字符串，如 "http://127.0.0.1:8080"
        :param timeout: 请求超时秒数
        """
        self.session = requests.Session()
        self.timeout = timeout
        
        # 处理 Cookie
        if cookies:
            if isinstance(cookies, str):
                # 将字符串 Cookie 转换为 dict
                cookie_dict = {}
                for item in cookies.split(';'):
                    if '=' in item:
                        k, v = item.strip().split('=', 1)
                        cookie_dict[k] = v
                self.session.cookies.update(cookie_dict)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)
        
        # 处理代理
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # 统一请求头
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
    
    def get(self, url, params=None, **kwargs):
        """发送GET请求，返回 (status_code, text)"""
        try:
            resp = self.session.get(url, params=params, timeout=self.timeout, proxies=self.proxies, **kwargs)
            return resp.status_code, resp.text
        except requests.exceptions.Timeout:
            logging.warning(f"请求超时: {url}")
        except requests.exceptions.ConnectionError:
            logging.warning(f"连接失败: {url}")
        except requests.exceptions.SSLError:
            logging.warning(f" SSL错误:{url}")
        except requests.exceptions.TooManyRedirects:
            logging.warning(f" 重定向过多:{url}")
        except requests.exceptions.InvalidURL:
            logging.warning(f" URL格式错误:{url}")
        except requests.exceptions.ProxyError:
            logging.warning(f" 代理错误:{url}")
        except requests.exceptions.ReadTimeout:
            logging.warning(f" 读取超时:{url}")
        except Exception as e:
            logging.debug(f"请求错误: {e}")

        return None, None
    
    def post(self, url, data=None, **kwargs):
        """发送POST请求，返回 (status_code, text)"""
        try:
            resp = self.session.post(url, data=data, timeout=self.timeout, proxies=self.proxies, **kwargs)
            return resp.status_code, resp.text
        except requests.exceptions.Timeout:
            logging.warning(f"请求超时: {url}")
        except requests.exceptions.ConnectionError:
            logging.warning(f"连接失败: {url}")
        except requests.exceptions.SSLError:
            logging.warning(f" SSL错误:{url}")
        except requests.exceptions.TooManyRedirects:
            logging.warning(f" 重定向过多:{url}")
        except requests.exceptions.InvalidURL:
            logging.warning(f" URL格式错误:{url}")
        except requests.exceptions.ProxyError:
            logging.warning(f" 代理错误:{url}")
        except requests.exceptions.ReadTimeout:
            logging.warning(f" 读取超时:{url}")
        except Exception as e:
            logging.debug(f"请求错误: {e}")
        return None, None

# 保留简单的独立函数，防止旧代码引用报错
def send_get_request(url, params=None, timeout=5):
    """简单的GET请求函数，兼容旧代码"""
    try:
        resp = requests.get(url, params=params, timeout=timeout)
        return resp.status_code, resp.text
    except Exception as e:
        logging.debug(f"请求失败: {e}")
        return None, None