import requests
from concurrent.futures import ThreadPoolExecutor
def check_path(base_url,path):
    full_url = base_url + path
    try:
        r = requests.get(full_url,timeout = 3)
        if r.status_code == 200:
            print(f"[+] 发现：{full_url} (状态码：{r.status_code})")
        elif r.status_code == 403:
            print(f"[*] 禁止访问：{full_url} (状态码：{r.status_code})")
        else:
            print(f"[] {full_url} (状态码：{r.status.code})") 
    except:
        print(f"[-] 连接失败：{full_url}")
        pass
base_url ="http://127.0.0.1:5000"
    #常用路径字典
paths = [
        "/", "/admin", "/login", "/api", "/user" ,
        "/test", "/backup", "/config", "/.git", "/robots.txt",
        "/static", "/upload", "/console", "/debug", "/health"
    ]
print(f"[*] 开始扫描{base_url},共{len(paths)}个路径")
print("=" * 40)
#用线程池并发扫描
with ThreadPoolExecutor(max_workers = 10 ) as executor:
    for path in paths:
        executor.submit(check_path,base_url,path)
print("=" * 40)
print("[+] 扫描完成")
