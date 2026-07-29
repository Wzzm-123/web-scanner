#从自己的工具库导用函数
from day3_utils import send_get_request
url = "http://127.0.0.1:5000/user"
#1,正常请求
print("[*] 正常发送请求。。。")
status_normal,text_normal = send_get_request(url,{"id" : "1"})
if status_normal is None:
    print("[-] 正常请求失败，靶场可能未启动，脚本退出")
    exit()
#2,注入测试请求
print("[*] 发送注入请求。。。")
status_attack,text_attack = send_get_request(url,{"id" : "1'"})
if status_attack is None:
    print("[-] 注入请求失败，脚本退出")
    exit()
#3,分析结果
print("/n" + "="*40)
print("[*] 分析结果：")
#健壮的逻辑判断
if status_attack == 500 or "error" in text_attack.lower() or "错误" in text_attack:
    print("[!] 高危:服务器返回错误,可能存在sql注入点")
elif len(text_normal) != len(text_attack):
    print("[!] 可疑：响应长度不同，需要进一步分析")
    print(f"    正常请求长度：{len(text_normal)}")
    print(f"    注入请求长度：{len(text_attack)}")
else:
    print("[+] 无异常：目标对异常输入反应正常")
print("=" * 40)


