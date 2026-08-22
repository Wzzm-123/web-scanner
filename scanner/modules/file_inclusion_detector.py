from core.requester import Requester
import urllib.parse

def check_file_inclusion(base_url, param_name, requester=None):
    """
    检测文件包含漏洞：尝试读取靶场自身的源代码。
    如果响应中包含源代码特征，判定存在漏洞。
    """
    if requester is None:
        requester = Requester()

    # 测试payload：尝试读取靶场自己的源代码
    payload = "file_inclusion_target.py"

    parsed = urllib.parse.urlparse(base_url)
    params = urllib.parse.parse_qs(parsed.query)
    params[param_name] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

    status, text = requester.get(test_url)

    if text:
        # 如果响应中包含源代码特征，说明文件被读取了
        source_markers = ["import flask", "from flask", "app = Flask"]
        for marker in source_markers:
            if marker in text:
                return True

    return False

if __name__ == "__main__":
    target = "http://127.0.0.1:5005/view?page=home"
    param = "page"
    if check_file_inclusion(target, param):
        print("[+] 存在文件包含漏洞")
    else:
        print("[-] 未检测到文件包含漏洞")