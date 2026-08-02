import sqlite3

DB_FILE = "scan_results.db"

def init_db():
    """初始化数据库，创建结果表"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        status_code INTEGER,
        length INTEGER,
        discovered_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def save_result(url, status_code, length):
    """保存一条扫描结果"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scan_results (url, status_code, length) VALUES (?, ?, ?)",
        (url, status_code, length)
    )
    conn.commit()
    conn.close()

def get_all_results():
    """获取所有扫描结果"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM scan_results ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return rows
def get_statistics():#安全扫描概览仪表器盘
    """获取扫描统计摘要"""
    conn = sqlite3.Connection(DB_FILE)
    c = conn.cursor()
    #总记录数
    c.execute("SELECT COUNT(*) FROM scan_results")
    total = c.fetchall()[0]
    #唯一url数
    c.execute("SELECT COUNT(DISTINCT url) FROM scan_results")
    unique_urls = c.fetchall()[0]
    #按状态码统计
    c.execute("SELECT status_code,COUNT(*) FROM scan_results GROUP BY status_code")
    status_stats = c.fetchall()
    conn.close()
    return total,unique_urls,status_stats
def search_by_keyword(keyword):
    """根据关键词搜索url"""
    conn = sqlite3.Connection(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT *FROM scan_results WHERE url LIKE ? ORDER BY id BESC",(f"%{keyword}%",))
    rows = c.fetchall()
    conn.close()
    return rows