from flask import Flask, request, render_template_string

app = Flask(__name__)

# 反射型XSS：直接输出参数
@app.route('/reflect')
def reflect():
    user_input = request.args.get('q', '')
    # 故意不做任何过滤，直接拼接到HTML
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

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)