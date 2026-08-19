from flask import Flask, request, render_template_string, redirect, url_for
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 主页面：上传表单
@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = file.filename
            # 第一层防御：前端JS会检查文件名，这里后端不检查，故意留漏洞
            # 第二层防御：检查MIME（Content-Type），但可以绕过
            if file.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
                return "文件类型不允许！只允许图片格式。"
            
            file.save(os.path.join(UPLOAD_FOLDER, filename))
            return f"上传成功！文件路径：/uploads/{filename}"
    # 前端JS校验：只允许 .jpg/.png/.gif（可被绕过）
    form = '''
    <h2>文件上传靶场（学习用）</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" accept=".jpg,.png,.gif" onchange="checkFile(this)">
        <input type="submit" value="上传">
    </form>
    <script>
        function checkFile(input) {
            var fileName = input.files[0].name;
            var ext = fileName.substring(fileName.lastIndexOf('.') + 1).toLowerCase();
            if (ext !== 'jpg' && ext !== 'png' && ext !== 'gif') {
                alert('只允许上传jpg/png/gif文件！');
                input.value = '';
            }
        }
    </script>
    '''
    return render_template_string(form)

# 提供上传文件的访问
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return f"文件已上传，但本靶场不解析PHP，请自行验证。"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=True)