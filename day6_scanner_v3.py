import argparse
from concurrent.futures import ThreadPoolExecutor
from day3_utils import send_get_request
from day5_db_utils import init_db,save_result,get_statistics,search_by_keyword
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
            status,text = future.result()
            if status in(200,403,301,302):
                length = len(text) if text else 0
                print(f"[+] 发现:{full_url},(长度：{length})")
                save_result(full_url,status,length)
                found.append(path)
    unique_found = list(set(found))
    print("=" * 40)
    print(f"[*]扫描完成，共发现{len(unique_found)}个可访问路径\n")
    for path in unique_found:
        print(f"    -{path}")
    #自动生成扫描报告
    generate_report()
    return unique_found
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web目录扫描器 V0.2")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-d", "--dict", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数")
    parser.add_argument("-s", "--search",help="搜索url关键词(查看历史记录)")
    args = parser.parse_args()
    if args.search:
        #历史搜索模式
        print(f"\n[*] 搜索包含{'args.search'}的历史记录")
        results = search_by_keyword(args.search)
        if results:
            for row in results:
                print(f"  {row[1]} (状态码：{row[2]}),长度:{row[3]},响应时间:{row[4]}")
            print(f"\n[+] 共找到{len(results)}条记录")
        else:
            print("[-] 没有找到匹配的记录")
    else:
        #正常扫描模式
        if not args.url:
            print("[-] 扫描模式需要制定-u参数(目标URL)")
        else:
             init_db()
             #打印历史统计摘要
             print("\n[*] 历史扫描统计:")
             total,unique_url,status_stats = get_statistics()
             print(f"   总记录数：{total}")
             print(f"   唯一url数:{unique_url}")
             print(f"   状态码分布:")
             for sc ,count in status_stats:
                 print(f"   {sc}:{count}个")
             print()
             #开始扫描
             scan_directory(args.url, args.dict, args.threads)