import requests

url = "http://127.0.0.1:5000/user"

# 正常请求
normal_params = {"id": "1"}
r_normal = requests.get(url, params=normal_params)
print(f"[正常] 状态码: {r_normal.status_code}, 长度: {len(r_normal.text)}")

# 注入测试：加单引号
attack_params = {"id": "1'"}
r_attack = requests.get(url, params=attack_params)
print(f"[注入测试] 状态码: {r_attack.status_code}, 长度: {len(r_attack.text)}")

# 简单判断
if r_attack.status_code == 500 or "error" in r_attack.text.lower():
    print("[!] 注意！返回了错误信息，可能存在SQL注入点。")
elif len(r_normal.text) != len(r_attack.text):
    print("[!] 页面长度不同，可能需要进一步分析。")
else:
    print("[+] 暂未发现明显差异。")