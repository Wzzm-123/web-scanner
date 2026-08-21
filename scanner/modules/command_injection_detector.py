from core.requester import Requester
import requests
def check_command_injection(base_url,parma_name,requester = None):
    """
    使用Requester类检测GET参数是否存在命令注入
    返回Ture/False
    """
    #如果没有传入Requester参数，就创建一个默认的
    if requester is None:
        requester = Requester()
    #测试标记，一个独一无二的字符串
    marker = "INJECT_TEST_MARKER_12345"
    #windows兼容的payload列表
    payloads = [
        f"127.0.0.1 & echo {marker}",
        f"127.0.0.1 && echo {marker}",
        f"127.0.0.1 | echo {marker}",
        f"127.0.0.1 || echo {marker}"
    ]
    #遍历payload，监测响应中是否出现标记
    for payload in payloads:
        #构建url:替换参数值
        import urllib.parse
        parsed = urllib.parse.urlparse(base_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[parma_name] = [payload]
        new_query = urllib.parse.urlencode(params,doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query = new_query))
        status,text = requester.get(test_url)
        if text and marker in text:
            return True
    return False
if __name__ == "__main__":
    #使用实例:直接检测到本地靶场
    target = "http://127.0.0.1:5004/ping?host=127.0.0.1"
    param = "host"
    if check_command_injection(target,param):
        print(f"[+] 存在命令注入")
    else:
        print(f"[-] 未检测到命令注入")


