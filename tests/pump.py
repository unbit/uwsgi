def app(req):
    print(req)
    ret = {
        "status": 200,
        "headers": {
            "content_type": "text/html",
            "foo": ['bar0', 'bar1', 'bar2']
        },
        "body": "<h1>Hello!</h1>",
    }
    print(ret)
    return ret
