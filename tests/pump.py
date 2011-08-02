def app(req):
  print(req)
  ret = {"status": 200,
          "headers": {"content_type": "text/html"},
          "body": "<h1>Hello!</h1>"}
  print(ret)
  return ret
