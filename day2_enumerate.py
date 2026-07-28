import requests
url = "http://127.0.0.1:5000/user"
print("开始遍历")
for i in range (1,11): #从1到10
    params = {"id" : str(i)} #http的参数传递必须为字符串
    r = requests.get(url,params = params)
    #如果返回的内容包含“返回成功”，说明这个id存在
    if "查询成功" in r.text:
       print(f"[+] ID = 1 存在! ->{r.text.strip()}")
    else:
        print(f"[-] ID不存在!")
print("遍历结束")