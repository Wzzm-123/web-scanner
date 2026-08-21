import argparse
from concurrent.futures import ThreadPoolExecutor
from core.requester import Requester
from db.database import (
    init_db, save_result, get_statistics, search_by_keyword,
    save_sql_vul, save_xss_vul
)
from report.generator import generate_report
from modules.sql_injection import check_sql_injection, guess_columns, auto_dump_injection
from modules.xss_detection import check_xss


def load_dict(filename):
    """从字典文件中加载路径"""
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def scan_directory(base_url, dict_file, threads=10, requester=None):
    """多线程目录扫描，结果存入数据库，使用 Requester 支持 Cookie/代理"""
    if requester is None:
        requester = Requester()
    paths = load_dict(dict_file)
    print(f"[*] 加载了 {len(paths)} 个路径，启动 {threads} 个线程")
    print("=" * 40)
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_path = {}
        for path in paths:
            full_url = base_url + path
            future = executor.submit(requester.get, full_url)
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
    parser = argparse.ArgumentParser(description="Web目录扫描器 V3.1（模块化 + Cookie/代理支持）")
    parser.add_argument("-u", "--url", required=True, help="目标URL（根目录或具体页面）")
    parser.add_argument("-d", "--dict", default="dict.txt", help="字典文件路径")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数")
    parser.add_argument("-s", "--search", help="搜索URL关键词（查看历史记录）")
    parser.add_argument("--sql-param", help="指定要检测SQL注入的GET参数（如 id）")
    parser.add_argument("--xss-param", help="指定要检测XSS的GET参数（如 q）")
    parser.add_argument("--cookie", help="Cookie字符串，例如 'PHPSESSID=abc123; username=admin'")
    parser.add_argument("--proxy", help="HTTP代理地址，例如 'http://127.0.0.1:8080'")
    args = parser.parse_args()

    # 创建 Requester 实例
    requester = Requester(cookies=args.cookie, proxy=args.proxy)

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
        # 打印历史统计摘要
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
            scan_directory(args.url, args.dict, args.threads, requester)
        else:
            # 如果 URL 包含参数，进行漏洞检测
            if args.sql_param:
                print("\n" + "=" * 60)
                print(f"[*] 开始SQL注入检测：{args.url} 参数: {args.sql_param}")
                print("=" * 60)
                vul_info = check_sql_injection(args.url, args.sql_param)
                if vul_info["has_inject"]:
                    print(f"[+] 检测到SQL注入漏洞！类型: {vul_info['inject_type']}")
                    cols = guess_columns(args.url, args.sql_param, inject_type=vul_info['inject_type'])
                    print(f"[+] 查询字段列数：{cols}")
                    save_sql_vul(
                        args.url,
                        args.sql_param,
                        vul_info['inject_type'],
                        cols,
                        "",
                        []
                    )
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

            if args.xss_param:
                print("\n" + "=" * 60)
                print(f"[*] 开始XSS检测：{args.url} 参数: {args.xss_param}")
                print("=" * 60)
                xss_result = check_xss(args.url, args.xss_param)
                if xss_result["has_xss"]:
                    print(f"[+] 检测到反射型XSS！payload: {xss_result['payload']}")
                    save_xss_vul(args.url, args.xss_param, xss_result['payload'], xss_result['evidence'])
                else:
                    print("[-] 未检测到反射型XSS。")
                print("=" * 60)

            if not args.sql_param and not args.xss_param:
                print("[-] URL 包含参数，但未指定 --sql-param 或 --xss-param。")
                print("    示例: python main.py -u \"http://127.0.0.1:8080/Less-1/?id=1\" --sql-param id")