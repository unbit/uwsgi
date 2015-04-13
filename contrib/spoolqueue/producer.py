from tasksconsumer import enqueue


def application(env, sr):

    sr('200 OK', [('Content-Type', 'text/html')])

    enqueue(queue='fast', pippo='pluto')

    return "Task enqueued"
