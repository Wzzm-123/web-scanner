from day5_db_utils import get_all_results

def generate_report(output_file="scan_report.txt"):
    """生成扫描报告"""
    results = get_all_results()
    
    if not results:
        print("[-] 没有扫描结果，无法生成报告。")
        return
    
    #按URL去重，只保留每条最新url的记录
    unique_results={}
    for row in results:
        url = row[1]
        #只保留第一次出现的数据
        if url not in unique_results:
            unique_results[url] = row
    with open (output_file,"w",encoding="utf-8") as f:
        f.write("=" * 50 + "\n")
        f.write("web漏洞扫描器-扫描报告\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"扫描时间: {unique_results[list(unique_results.keys())[0]][4] if unique_results else '无'}\n")
        f.write(f"共发现{len(unique_results)}个唯一可访问路径")
        f.write("=" * 50 + "\n\n")
        for url,row in unique_results.items():
            f.write(f"URL:{row[1]}\n")
            f.write(f"状态码:{row[2]}\n")
            f.write(f"响应长度:{row[3]}字节\n")
            f.write(f"发现时间:{row[4]}\n")
print(f"[+] 报告已生成:{"output_file"}")
        
        
