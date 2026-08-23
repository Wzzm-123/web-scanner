from core.requester import Requester
import urllib.parse
def check_ssrf(base_url,param_name,requester = None):
    """
    检测SSRF漏洞:尝试让服务器请求一个内网地址,检查响应中是否包含响应预期
    这里用本地HTTP协议作为目标
    """
    if requester is None:
        requester = Requester()
    payload = "http://127.0.0.1:8000"
    #构造URL
    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)
    params[param_name] = [payload]
    new_query = urllib.parse.urlencode(params,doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query = new_query))
    status,text = requester.get(test_url)
    if text:
        "如果返回的内容包含目录列表的特征,说明SSRF成功"
        if "Directory listing" in text or "Index" in text:
            return True
    return False
if __name__ == "__main__":
    target = "http://127.0.0.1:5006/fetch?url=http://127.0.0.1:5005/"
    param = "url"
    if check_ssrf(target,param):
        print(f"[+] 存在SSRF漏洞")
    else:
        print(f"[-] 未检测到SSRF漏洞")
