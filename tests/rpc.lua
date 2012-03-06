function hello()
	return "Hello i am Lua"
end

function hello2()
	return "Hello i am Lua [2]"
end

function hello3(arg1)
	return "Hello i am a Lua function with 1 arg "..arg1
end

function hello4(arg1, arg2)
	return "Hello i am a Lua function with 2 args "..arg1.." "..arg2
end

uwsgi.register_rpc("hello", hello)
uwsgi.register_rpc("hello2", hello2)
uwsgi.register_rpc("hello3", hello3)
uwsgi.register_rpc("hello4", hello4)
