config = {}

config[1] = { ['http-socket']=':9090' }
config[2] = { ['env']='FOO=bar' }
config[3] = { ['env']='TEST=topogigio' }
config[4] = { ['module']='werkzeug.testapp:test_app' }

return config
