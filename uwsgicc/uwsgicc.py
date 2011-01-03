import uwsgi
from flask import Flask, render_template, request, url_for, redirect, flash
import time
import os

app = Flask(__name__)
app.debug = True
app.secret_key = os.urandom(24)

@app.template_filter('unixtime')
def unixtime(s):
    return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(s))


@app.route("/")
def index():
    return render_template("index.html", uwsgi=uwsgi)

@app.route("/log", methods=['POST'])
def log():
    uwsgi.log(request.form['message'])
    flash("log message written")
    return redirect(url_for('index'))
