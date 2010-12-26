function hello_signal(sig, payload)

	print("i am Lua received signal " .. sig .. " with payload " .. payload)

end

uwsgi.register_signal(1, 1, hello_signal, "roberta")
uwsgi.register_signal(2, 1, hello_signal, "serena")
uwsgi.register_signal(3, 1, hello_signal, "alessandro")
