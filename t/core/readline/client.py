import requests

headers = {'Content-Type': 'application/octet-stream'}
data = '\n'.join(['{:04}'.format(i) for i in range(1001)] + ['final'])

r = requests.post("http://127.0.0.1:8000", data=data, headers=headers)

assert r.text == data
