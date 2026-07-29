import requests

url = "http://127.0.0.1:5000/user"

# 正常请求
r1 = requests.get(url, params={"id": "1"})
print("正常请求状态码:", r1.status_code)
print("正常请求长度:", len(r1.text))

# 注入请求
r2 = requests.get(url, params={"id": "1'"})
print("注入请求状态码:", r2.status_code)
print("注入请求长度:", len(r2.text))
print("注入请求内容:")
print(r2.text)

# 最简单的判断
if r2.status_code == 500 or "error" in r2.text.lower():
    print("[!] 发现注入点！")
elif len(r1.text) != len(r2.text):
    print("[!] 长度不同，可疑！")
else:
    print("[+] 无异常")