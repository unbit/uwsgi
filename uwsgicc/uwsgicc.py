import uwsgi
from flask import Flask, render_template
import time

app = Flask(__name__)

@app.template_filter('unixtime')
def unixtime(s):
    return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(s))


@app.route("/")
def index():
    return render_template("index.html", uwsgi=uwsgi)
