import argparse
from concurrent.futures import ThreadPoolExecutor
from day3_utils import send_get_request
def load_dict(filename):
    """从字典文件加载路径"""
    with open(filename,"r",encoding="utf - 8") as f:
        return[line.strip() for line in f if line.strip and not line.startswith("#")]
def scan_directory(base_url,dict_file,threads = 10):
    """多线程目录扫描"""
    paths = load_dict(dict_file)
    print(f"[*] 加载了{len(paths)}个路径，启动{threads}个线程")
    print("=" * 40)
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        #提交所有任务
        future_to_path = {
             executor.submit(send_get_request, base_url + path): path 
            for path in paths
        }
        #处理结果
        for future in future_to_path:
            path = future_to_path[future]
            status, text = future.result()
            if status == 200:
                print(f"[+] 发现: {base_url}{path} (长度: {len(text) if text else 0})")
                found.append(path)

    print("=" * 40)
    print(f"[*] 扫描完成，共发现 {len(found)} 个可访问路径")
    return found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web目录扫描器 V0.1")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-d", "--dict", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数")
    args = parser.parse_args()

    scan_directory(args.url, args.dict, args.threads)