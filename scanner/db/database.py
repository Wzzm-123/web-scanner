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
    total = c.fetchone()[0]
    #唯一url数
    c.execute("SELECT COUNT(DISTINCT url) FROM scan_results")
    unique_urls = c.fetchone()[0]
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
def init_sql_vul_table():
    """初始化SQL漏洞表"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS sql_vul (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        param TEXT,
        inject_type TEXT,
        column_count INTEGER,
        db_name TEXT,
        tables TEXT,
        found_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def save_sql_vul(url, param, inject_type, column_count=0, db_name="", tables=None):
    """保存SQL注入漏洞记录"""
    if tables is None:
        tables = []
    init_sql_vul_table()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO sql_vul (url, param, inject_type, column_count, db_name, tables) VALUES (?, ?, ?, ?, ?, ?)",
        (url, param, inject_type, column_count, db_name, ",".join(tables))
    )
    conn.commit()
    conn.close()
def init_xss_table():
    """初始化XSS漏洞表"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS xss_vul (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        param TEXT,
        payload TEXT,
        evidence TEXT,
        found_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def save_xss_vul(url, param, payload, evidence=""):
    """保存XSS漏洞记录"""
    init_xss_table()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO xss_vul (url, param, payload, evidence) VALUES (?, ?, ?, ?)",
        (url, param, payload, evidence)
    )
    conn.commit()
    conn.close()

