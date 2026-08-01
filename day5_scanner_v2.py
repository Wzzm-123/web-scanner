import argparse
from concurrent.futures import ThreadPoolExecutor
from day3_utils import send_get_request
from day5_db_utils import init_db,save_result
from day5_report import generate_report
def load_dict(filename):
    """从字典文件中加载路径"""
    with open(filename,"r",encoding="utf-8")as f:
        return[line.strip() for line in f if line.strip() and  not line.startswith("#")]
def scan_directory(base_url,dict_file,threads=10):
    """多线程目录扫描，结果存入数据库"""
    paths = load_dict(dict_file)
    print(f"[*] 加载了{len(paths)}个路径，启动{threads}个线程")
    print("=" * 40)
    found = []
    with ThreadPoolExecutor(max_workers = threads) as executor:
        future_to_path = {}
        for path in paths:
            full_url = base_url + path
            future = executor.submit(send_get_request,full_url)
            future_to_path[future] = (path,full_url)
        for future in future_to_path:
            path,full_url = future_to_path[future]
            status,test = future.result()
            if status in(200,403,301,302):
                length = len(test) if test else 0
                print(f"[+] 发现:{full_url},(长度：{length})")
                save_result(full_url,status,length)
                found.append(path)
    unique_found = list(set(found))
    print("=" * 40)
    print(f"[*]扫描完成，共发现{len(unique_found)}个可访问路径")
    for path in unique_found:
        print(f"    -{path}")
    generate_report()
    return unique_found
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web目录扫描器 V0.2")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-d", "--dict", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数")
    args = parser.parse_args()
    init_db()
    scan_directory(args.url, args.dict, args.threads)






    

