import argparse
from concurrent.futures import ThreadPoolExecutor
from day3_utils import send_get_request
from day5_db_utils import init_db, save_result, get_statistics, search_by_keyword, save_sql_vul
from day5_report import generate_report
from sql_injection import check_sql_injection, guess_columns, auto_dump_injection
from xss_detection import check_xss
from day5_db_utils import save_xss_vul
def load_dict(filename):
    """从字典文件中加载路径"""
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def scan_directory(base_url, dict_file, threads=10):
    """多线程目录扫描，结果存入数据库"""
    paths = load_dict(dict_file)
    print(f"[*] 加载了 {len(paths)} 个路径，启动 {threads} 个线程")
    print("=" * 40)

    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {}
        for path in paths:
            full_url = base_url + path
            future = executor.submit(send_get_request, full_url)
            future_to_path[future] = (path, full_url)

        for future in future_to_path:
            path, full_url = future_to_path[future]
            status, text = future.result()
            if status in (200, 403, 301, 302):
                length = len(text) if text else 0
                print(f"[+] 发现: {full_url} (状态码: {status}, 长度: {length})")
                save_result(full_url, status, length)
                found.append(path)

    unique_found = list(set(found))
    print("=" * 40)
    print(f"[*] 扫描完成，共发现 {len(unique_found)} 个唯一可访问路径：")
    for path in unique_found:
        print(f"    - {path}")

    generate_report()
    return unique_found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web目录扫描器 V3.1(集成SQL注入检测)")
    parser.add_argument("-u", "--url", required=True, help="目标URL(根目录或具体页面)")
    parser.add_argument("-d", "--dict", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数")
    parser.add_argument("-s", "--search", help="搜索URL关键词(查看历史记录）")
    parser.add_argument("--sql-param", help="指定要检测SQL注入的GET参数(如 i)")
    parser.add_argument("--xss-param",help = "指定要检测xss的GET参数(如q)")
    args = parser.parse_args()

    # 历史搜索模式
    if args.search:
        print(f"\n[*] 搜索包含 '{args.search}' 的历史记录：")
        results = search_by_keyword(args.search)
        if results:
            for row in results:
                print(f"  {row[1]} (状态码: {row[2]}, 长度: {row[3]}, 时间: {row[4]})")
            print(f"\n[+] 共找到 {len(results)} 条记录")
        else:
            print("[-] 没有找到匹配的记录。")
    else:
        init_db()
        # 打印历史统计摘要（已修复 fetchone()[0] 问题）
        print("\n[*] 历史扫描统计：")
        total, unique_urls, status_stats = get_statistics()
        print(f"    总记录数: {total}")
        print(f"    唯一URL数: {unique_urls}")
        print("    状态码分布:")
        for sc, count in status_stats:
            print(f"      {sc}: {count} 个")
        print()

        # 目录扫描模式（如果 URL 不包含参数）
        if "?" not in args.url:
            print(f"[*] 开始目录扫描：{args.url}")
            scan_directory(args.url, args.dict, args.threads)
        else:
            # 如果 URL 包含参数，只进行 SQL 注入检测（需要指定 --sql-param）
            if args.sql_param:
                print("\n" + "=" * 60)
                print(f"[*] 开始SQL注入检测：{args.url} 参数: {args.sql_param}")
                print("=" * 60)
                vul_info = check_sql_injection(args.url, args.sql_param)
                if vul_info["has_inject"]:
                    print(f"[+] 检测到SQL注入漏洞！类型: {vul_info['inject_type']}")
                    # 猜列数
                    cols = guess_columns(args.url, args.sql_param, inject_type=vul_info['inject_type'])
                    print(f"[+] 查询字段列数：{cols}")
                    # 保存漏洞信息
                    save_sql_vul(
                        args.url,
                        args.sql_param,
                        vul_info['inject_type'],
                        cols,
                        "",
                        []
                    )
                    # 自动脱库
                    print("\n[*] 开始自动脱库...")
                    dump_result = auto_dump_injection(args.url, args.sql_param)
                    if dump_result:
                        print("\n" + "=" * 50)
                        print(f"数据库名: {dump_result['db_name']}")
                        print(f"所有表: {dump_result['tables']}")
                        print(f"目标表: {dump_result['target_table']}")
                        print(f"字段: {dump_result['columns']}")
                        print("数据内容:")
                        for row in dump_result['data']:
                            print(f"  {row}")
                        print("=" * 50)
                    else:
                        print("[-] 脱库失败")
                else:
                    print("[-] 未检测到SQL注入漏洞。")
                print("=" * 60)
            else:
                print("[-] URL 包含参数，但未指定 --sql-param,无法进行SQL注入检测。")
                print("    示例: python day6_scanner_v3.py -u \"http://127.0.0.1:8080/Less-1/?id=1\" --sql-param id")
        #==============xss检测逻辑===============
        if args.xss_param:
            print("\n" + "=" * 60)
            print(f"[*]开始xss检测:{args.url} 参数:{args.xss_param}")
            print("=" *60)
            xss_result = check_xss(args.url,args.xss_param)
            if xss_result["has_xss"]:
                print(f"[+] 检测到反射型xss! payload:{xss_result['payload']}")
                save_xss_vul(args.url,args.xss_param,xss_result['payload'],xss_result['evidence'])
            else:
                print("[-] 未检测到反射型xss")
            print("=" * 60)


