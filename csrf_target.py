from flask import Flask, request, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = 'test-secret'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session['username'] = 'victim'
        return redirect(url_for('profile'))
    return '''
    <form method="POST">
        <input type="text" name="username" value="victim">
        <input type="submit" value="登录">
    </form>
    '''

@app.route('/profile')
def profile():
    username = session.get('username')
    if not username:
        return '请先登录'
    return f'<h2>欢迎，{username}</h2><a href="/change_password?new_password=hacked">修改密码（演示）</a>'

@app.route('/change_password')
def change_password():
    username = session.get('username')
    if not username:
        return '请先登录'
    new_password = request.args.get('new_password')
    # 模拟修改密码
    return f'用户 {username} 的密码已被修改为 {new_password}'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5003, debug=True)