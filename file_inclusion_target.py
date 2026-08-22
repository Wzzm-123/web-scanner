import os
from flask import Flask, request

app = Flask(__name__)

# 模拟合法页面
pages = {
    'home': '这是首页内容',
    'about': '这是关于页面',
    'contact': '这是联系页面',
}

@app.route('/')
def index():
    return '''
    <h2>文件包含靶场</h2>
    <ul>
        <li><a href="/view?page=home">首页</a></li>
        <li><a href="/view?page=about">关于</a></li>
        <li><a href="/view?page=contact">联系</a></li>
    </ul>
    '''

@app.route('/view')
def view():
    # 关键：先获取用户参数
    page = request.args.get('page', 'home')

    # 如果 page 在合法字典中，直接返回内容
    if page in pages:
        content = pages[page]
    else:
        # 否则尝试读取文件（漏洞点）
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, page)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            content = f"文件不存在或无法读取: {e}"

    return f"<pre>{content}</pre>"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5005, debug=True)