import requests
url = "http://httpbin.org/get"
#方式一，参数直接拼接在url里
params = {"name": "你的名字","tool" :"python"}
response = requests.get(url,params = params)
print("实际请求的URL是:,response.url")
print("服务器返回的完整内容:,response.text")
print(response.text)

