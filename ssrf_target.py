import requests
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h2>SSRF靶场</h2>
    <form action="/fetch" method="GET">
        <input type="text" name="url" placeholder="输入要访问的URL，如 http://127.0.0.1:5005/">
        <input type="submit" value="获取内容">
    </form>
    '''

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    if not url:
        return "请输入URL参数。"
    
    # 漏洞点：服务器直接请求用户指定的URL
    try:
        resp = requests.get(url, timeout=5)
        content = resp.text[:500]  # 只显示前500字符
        return f"<pre>状态码: {resp.status_code}\n\n内容:\n{content}</pre>"
    except Exception as e:
        return f"请求失败: {e}"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5006, debug=True)