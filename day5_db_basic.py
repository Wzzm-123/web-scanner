import sqlite3

# 1. 连接数据库（如果文件不存在，会自动创建）
conn = sqlite3.connect("scan_results.db")
# 2. 创建一个“光标”，用来执行SQL语句
c = conn.cursor()

# 3. 创建一张表（如果表已经存在就跳过）
c.execute("""
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    status_code INTEGER,
    length INTEGER,
    discovered_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
print("[+] 表创建成功")

# 4. 插入一条数据（增）
c.execute(
    "INSERT INTO scan_results (url, status_code, length) VALUES (?, ?, ?)",
    ("http://127.0.0.1:5000/user", 200, 50)
)
conn.commit()  # 提交事务，真正写入文件
print("[+] 数据插入成功")

# 5. 查询数据（查）
c.execute("SELECT * FROM scan_results")
rows = c.fetchall()
print("\n[*] 当前数据库内容：")
for row in rows:
    print(f"  ID={row[0]}, URL={row[1]}, 状态码={row[2]}, 长度={row[3]}, 时间={row[4]}")

# 6. 关闭连接
conn.close()
print("\n[+] 数据库连接已关闭")