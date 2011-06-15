import uwsgi
from flask import Flask, render_template, request, url_for, redirect, flash
import time
import os
import socket

app = Flask(__name__)
app.debug = True
app.secret_key = os.urandom(24)

@app.template_filter('unixtime')
def unixtime(s):
    return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(s))


@app.route("/")
def index():
    return render_template("index.html", uwsgi=uwsgi, hostname=socket.gethostname(), uid=os.getuid(), gid=os.getgid(), cwd=os.getcwd())

@app.route("/log", methods=['POST'])
def log():
    uwsgi.log(request.form['message'])
    flash("log message written")
    return redirect(url_for('index'))

@app.route("/sig", methods=['POST'])
def sig():
    try:
        uwsgi.signal(int(request.form['signum']))
        flash("uwsgi signal sent")
    except:
        flash("unable to send signal")
    return redirect(url_for('index'))

@app.route("/rpc", methods=['POST'])
def rpc():
    node = str(request.form['node'])

    fargs = str(request.form['args'])

    args = fargs.split()


    if len(args) > 0:
        ret = uwsgi.rpc(str(node), str(request.form['func']), *map(str, args))
    else:
        ret = uwsgi.rpc(str(node), str(request.form['func']))

    #flash("rpc \"%s\" returned: %s" % (request.form['func'], ret) )

    return ret
    #return redirect(url_for('index'))
