import requests
#一个专门用来测试的网站
url = "http://127.0.0.1:5000/user?id=1"
#发送get请求
response = requests.get(url)
#打印结果
print(f"状态码:{response.status_code}")
print(f"响应头:{response.headers}")
print(f"响应体前200字:{response.text[:200]}")