import sqlite3
conn = sqlite3.connect("scan_results.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_results(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     url TEXT NOT NULL,
     status_code INTEGER,
     length INTEGER,
     discovered_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
print("[+] 表创建成功")
cursor.execute(
    "INSERT INTO scan_results (url,status_code,length) VALUES (?,?,?)",
    ("http://127.0.0.1:5000/user",200,50)
)
conn.commit()
print("[+] 插入数据成功")
cursor.execute("SELECT * FROM scan_results")
rows = cursor.fetchall()
print("\n[*] 当前数据库内容：")
for row in rows:
    print(f"  ID={row[0]},URL={row[1]},状态码={row[2]},长度={row[3]},时间={row[4]}")
conn.close()
print("\n[*] 数据库连接已关闭")



