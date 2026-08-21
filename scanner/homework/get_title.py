import requests
import re
def get_title(url):
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            match = re.search(r'<title>(.*?)</title>',resp.text,re.S)
            if match:
                return match.group(1).strip()
    except requests.exceptions.Timeout:
        print("连接超时")
    except requests.exceptions.ConnectionError:
        print("连接失败")
    except Exception as e:
        print(f"其他错误:{e}")
if __name__ == "__main__":
    title = get_title("http://127.0.0.1:5004/")
    print(f"页面标题:{title}")