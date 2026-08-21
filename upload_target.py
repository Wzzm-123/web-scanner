from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            return "没有文件"
        
        filename = file.filename
        
        # 第一层防御：前端JS校验（表单里已包含，但可被绕过）
        # 第二层防御：MIME检查（Content-Type）
        if file.content_type not in ['image/jpeg', 'image/png', 'image/gif']:
            return "文件类型不允许！只允许图片格式。"
        
        # 第三层防御：扩展名黑名单
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        blacklist = ['php', 'php3', 'php4', 'php5', 'phtml', 'pht']
        if ext in blacklist:
            return "文件扩展名不允许！"
        
        # 第四层防御：文件头校验（只允许GIF、JPEG、PNG）
        content = file.read()
        file.seek(0)
        # 简单判断文件头
        if content.startswith(b'GIF89a'):
            pass  # GIF文件头正常
        elif content.startswith(b'\xff\xd8\xff'):
            pass  # JPEG文件头正常
        elif content.startswith(b'\x89PNG\r\n\x1a\n'):
            pass  # PNG文件头正常
        else:
            return "文件内容不是合法图片！"
        
        # 保存文件
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return f"上传成功！文件路径：/uploads/{filename}"
    
    # 前端表单
    form = '''
    <h2>文件上传靶场（多层防御）</h2>
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

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return f"文件已上传，但本靶场不解析PHP，请自行验证。"

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=True)