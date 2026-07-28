import requests
url = "http://httpbin.org/post"
#模拟登录数据
data = {
    "username" : "admin",
    "password" : "123456"
}
#发送post请求
response = requests.post(url,data=data)
print("服务器返回的内容")
print(response.text)