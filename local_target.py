from flask import Flask, request
import sqlite3
app = Flask(__name__)

# 初始化一个简单数据库
def init_db():
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INT, username TEXT, password TEXT)")
    #多添加几个用户用于越权访问
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT INTO users VALUES (2, 'zhangsan' , 'zhangsan456')")
    c.execute("INSERT INTO users VALUES (3, 'liming' , '789liming')")
    conn.commit()
    conn.close()
@app.route('/user')
def get_user():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    # 这里故意拼接SQL语句，制造注入漏洞
    query = f"SELECT * FROM users WHERE id = {user_id}"
    try:
        c.execute(query)
        result = c.fetchone()
        conn.close()
        if result:
            return f"查询成功：ID={result[0]}, 用户名={result[1]}, 密码={result[2]}"
        else:
            return "无此用户"
    except Exception as e:
        conn.close()
        return f"SQL错误: {e}"

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)