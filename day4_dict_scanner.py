import requests
from concurrent.futures import ThreadPoolExecutor
def check_path(base_url,path):
    full_url = base_url + path
    try:
        r = requests.get(full_url,timeout = 3)
        if r.status_code == 200:
            print(f"[+] 发现：{full_url} (长度:{len(r.text)})")
    except:
        pass
def load_dict(filename):
    """从字典文件加载路径列表"""
    with open(filename,"r",encoding = "utf-8") as f:
        #读取每一行，去掉首尾空白，忽略空白或以#开头的注释行
        paths = []
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                paths.append(line)
        return paths
#加载字典
paths = load_dict("dict.txt")
print(f"[*] 从字典里加载了{len(paths)}个路径")
#扫描
base_url = "http://127.0.0.1:5000"
with ThreadPoolExecutor(max_workers=10) as executor:
    for path in paths:
        executor.submit(check_path,base_url,path)
print("[*] 扫描完成")

