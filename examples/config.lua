config = {}

config['immediate-uid'] = 'roberto'
config['immediate-gid'] = 'roberto'
config['http-socket'] = ':9090'
config['env'] = { 'FOO=bar', 'TEST=topogigio' }
config['module'] = 'werkzeug.testapp:test_app'

return config
