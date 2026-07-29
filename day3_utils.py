import requests
def send_get_request(url,params = None, timeout = 5):
    """
    通用的GET请求发送函数。
    返回：(状态码,响应文本)
    即使服务器返回错误状态码(如500),也会正常返回,不会当作异常 
    """
    try:
        r = requests.get(url,params = params,timeout = timeout)
        return r.status_code,r.text
    except requests.exceptions.Timeout:
        print(f"[-] 超时：{url}")
    except requests.exceptions.ConnectionError:
        print(f"[-] 连接失败：{url}")
    except Exception as e:
        print(f"[-] 请求错误：{e}")
    return None,None
#简单测试
if '_name_ '== "_main_":
    status,text = send_get_request("http://127.0.0.1:5000/user",{"id" : "1"})
    if status:
        print(f"状态码：{status}")
        print(f"内容：{text}")
