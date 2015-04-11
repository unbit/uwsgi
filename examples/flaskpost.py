from flask import Flask, request
app = Flask(__name__)
app.debug = True


@app.route('/')
def hello_world():
    return "<form method='POST' enctype='multipart/form-data' action='/upload'><input type='text' name='pippo'/><input type='file' name='ufile'/><input type='submit' value='upload'/></form>"


@app.route('/upload',  methods=['GET', 'POST'])
def upload_file():
    return str(len(request.form.get('pippo', 'boh'))) + request.form.get('pippo', 'boh')
    return request.files['ufile'].read()
