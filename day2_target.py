import requests
url = "http://127.0.0.1:5000/user"
#尝试获取id=1的用户
params1 = {"id" : "1" }
response1 = requests.get(url,params = params1)
print("id=1结果：",response1.text)
#尝试获取id=2的用户
params2 = {"id" : "2"}
response2 = requests.get(url,params = params2)
print("id=2结果:",response2.text) 
#尝试一个不存在的id
params3 = {"id" : "999"}
response3 = requests.get(url,params = params3)
print("id = 999结果:",response3.text)
#正常请求
r_normal = requests.get(url,params = {"id" : "1"})
#攻击请求
r_attack = requests.get(url,params ={"id" : "1'"})
print("/n正常请求长度：",len(r_normal.text))
print("攻击请求长度：",len(r_attack.text))
if r_attack.status_code == 500 or "error" in r_attack.text.lower():
    print("服务器返回错误，可能存在注入点")
elif len(r_attack.text) != len(r_normal.text):
    print("响应长度不同，需要进一步分析")
else:
    print("无明显异常")
