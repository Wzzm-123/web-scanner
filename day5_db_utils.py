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
