from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <html>
    <head>
        <title>命令注入靶场</title>
    </head>
    <body>
    <h2>命令注入靶场</h2>
    <form action="/ping" method="GET">
        <input type="text" name="host" placeholder="输入IP或域名，如 127.0.0.1">
        <input type="submit" value="Ping">
    </form>
    </body>
    </html>
    '''

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not host:
        return "请输入host参数。"
    
    # 漏洞点：直接拼接用户输入到系统命令
    command = f"ping -n 2 {host}"
    try:
        # 使用 subprocess 执行命令，捕获输出
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    
    return f"<pre>命令: {command}\n\n输出:\n{output}</pre>"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5004, debug=True)