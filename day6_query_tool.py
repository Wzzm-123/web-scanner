import sqlite3
from day5_db_utils import DB_FILE
def run_query(sql,params = None):
    conn = sqlite3.Connection(DB_FILE)
    c = conn.cursor()
    if params:
        c.execute(sql,params)
    else:
        c.execute(sql)
    rows = c.fetchall()
    conn.close()
    return rows
def print_results(rows,title = "查询结果"):
    """格式化打印查询结果"""
    print("\n" + "=" * 50)
    print(f"[*]{title}")
    print("=" * 50)
    if not rows:
        print("[-] 没有找到匹配记录")
        return
    print(f"[+] 共找到{len(rows)}条记录\n")
    for row in rows:
        print(f"  ID: {row[0]} |  URL: {row[1]}) | 响应状态: {row[2]} | 长度: {row[3]} | 响应时间: {row[4]}")
    print()
#=============================================
#以下为我自己的查询练习，用来观察运行结果
#=============================================
if __name__ == "__main__":
    # 查询1：查看所有结果
    rows = run_query("SELECT * FROM scan_results ORDER BY id DESC")
    print_results(rows, "所有扫描结果（按时间倒序）")
    
    # 查询2：只看状态码为200的页面
    rows = run_query("SELECT * FROM scan_results WHERE status_code = 200")
    print_results(rows, "状态码为200的可访问页面")
    
    # 查询3：统计每种状态码的页面数量
    rows = run_query("SELECT status_code, COUNT(*) FROM scan_results GROUP BY status_code")
    print("\n" + "=" * 50)
    print("[*] 状态码统计（GROUP BY）")
    print("=" * 50)
    for row in rows:
        print(f"  状态码 {row[0]}: {row[1]} 个页面")
    
    # 查询4：查询响应长度大于1000的页面
    rows = run_query("SELECT * FROM scan_results WHERE length > 1000")
    print_results(rows, "响应长度大于1000字节的页面")
    
    # 查询5：模糊查询，找出所有包含'admin'的URL
    rows = run_query("SELECT * FROM scan_results WHERE url LIKE '%admin%'")
    print_results(rows, "URL中包含'admin'的页面")
    
    # 查询6：只查最近5条记录
    rows = run_query("SELECT * FROM scan_results ORDER BY id DESC LIMIT 5")
    print_results(rows, "最近5条扫描记录")
    
    # 查询7：查某个特定URL的所有历史记录
    target_url = "http://127.0.0.1:5000/user"
    rows = run_query(
        "SELECT * FROM scan_results WHERE url = ? ORDER BY id DESC",
        (target_url,)
    )
    print_results(rows, f"URL [{target_url}] 的历史记录")