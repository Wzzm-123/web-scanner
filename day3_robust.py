import requests
#一个肯定连不上的网址，制造登录失败
bad_url = "http://192.168.255.255:9999/user"
#一个不存在的域名
fake_domain = "http://this-domain-does-not-exite-123456.com"
#正常的靶场地址
good_url = "http://127.0.0.1:5000/user"
def test_request(url,params = None):
    """尝试发送请求，并捕获所有可能的结果"""
    try:
        print(f"/n[*] 正在请求:{url}")
        r = requests.get(url,params = params,timeout = 5)
        print(f"[+] 成功! 状态码：{r.status_code}")
        print(f"[+] 内容前50字：{r.text[:50]}")
        return r 
    except requests.exceptions.Timeout:
        print(f"[-] 请求超时:服务器{url}在五秒内没有响应")
    except requests.exceptions.ConnectionError:
        print(f"[-] 连接失败：服务器{url}无法连接，请检查地址或网络" )
    except requests.exceptions.MissingSchema:
        print(f"[-] URL格式出现错误：{url}记得要加http哦")
    except Exception as e:
        print(f"[-] 未知错误：{e}")
    return None
#测试正常的地址
test_request(good_url,{"id" : "1"})
#测试一个无法连接的地址
test_request(bad_url)
#测试一个不存在的域名
test_request(fake_domain)



    



    
