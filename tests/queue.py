# uwsgi --queue 10 --queue-store test.queue --master --module tests.queue --socket :3031

import uwsgi
import os
from flask import Flask, render_template, request, redirect, flash

app = Flask(__name__)
app.debug = True
app.secret_key = os.urandom(24)


@app.route('/')
def index():
    return render_template('queue.html', uwsgi=uwsgi)


@app.route('/push', methods=['POST'])
def push_item():
    if uwsgi.queue_push(request.form['body']):
        flash('item enqueued')
        return redirect('/')
    else:
        flash('unable to enqueue item')
        return render_template('queue.html', uwsgi=uwsgi)


@app.route('/get', methods=['POST'])
def get_item():
    flash("slot %s value = %s" % (request.form['slot'], uwsgi.queue_get(int(request.form['slot']))))
    return redirect('/')


@app.route('/pop', methods=['POST'])
def pop_item():
    flash("popped value = %s" % uwsgi.queue_pop())
    return redirect('/')


@app.route('/pull', methods=['POST'])
def pull_item():
    flash("pulled value = %s" % uwsgi.queue_pull())
    return redirect('/')


@app.route('/set', methods=['POST'])
def set_item():
    if uwsgi.queue_set(int(request.form['pos']), request.form['body']):
        flash('item set')
        return redirect('/')
    else:
        flash('unable to set item')
        return render_template('queue.html', uwsgi=uwsgi)
