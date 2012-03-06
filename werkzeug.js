{
	"uwsgi": {
		"http": ":8080",
		"workers": 8,
		"module": "werkzeug.testapp:test_app",
		"master": true,
		"socket": [ "/tmp/uwsgi.sock", "127.0.0.1:3031", "@foobar" ],
		"pythonpath": [ "/foo", "/bar" ],
		"show-config": true
	}
}
