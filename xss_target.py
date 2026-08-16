from flask import Flask, request, render_template_string

app = Flask(__name__)

# 反射型XSS：直接输出参数
@app.route('/reflect')
def reflect():
    user_input = request.args.get('q', '')
    # 简单过滤：只删除一次 <script> 和 </script>
    user_input = user_input.replace('<script>', '').replace('</script>', '')
    template = f"<html><body>你搜索的内容是: {user_input}</body></html>"
    return render_template_string(template)

# 存储型XSS：把评论存到列表并显示
comments = []

@app.route('/stored', methods=['GET', 'POST'])
def stored():
    if request.method == 'POST':
        comment = request.form.get('comment', '')
        comments.append(comment)
    # 显示所有评论，不做过滤
    comment_html = "".join(f"<div>{c}</div>" for c in comments)
    form = '''
    <form method="POST">
        <input type="text" name="comment" placeholder="输入评论">
        <input type="submit" value="提交">
    </form>
    '''
    return render_template_string(f"<html><body>{form}<hr>{comment_html}</body></html>")
@app.route('/dom2')
def dom2():
    return '''
    <html><body>
    <h1>DOM XSS Demo (URL参数)</h1>
    <div id="content"></div>
    <script>
        var params = new URLSearchParams(window.location.search);
        var q = params.get('q');
        document.getElementById("content").innerHTML = decodeURIComponent(q);
    </script>
    </body></html>
    '''
@app.route('/steal')
@app.route('/steal')
def steal():
    cookie = request.args.get('cookie', '')
    with open('stolen_cookies.txt', 'a', encoding='utf-8') as f:
        if cookie:
            f.write(cookie + '\n')
        else:
            f.write('(empty cookie)\n')
    print(f"[+] 接收到窃取的Cookie: {cookie}")
    return 'ok'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)