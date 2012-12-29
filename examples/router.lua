print("uWSGI Lua router")

uwsgi.log("i am ready")

function route(env)

	print(env.REQUEST_URI)

	html = uwsgi.cache_get(env.REQUEST_URI)

	local function send_cache()
		coroutine.yield(html)
	end

	local function body()
		page = ""
		parts = { uwsgi.send_message("127.0.0.1:3033", 0, 0, env, 30, uwsgi.req_fd(), uwsgi.cl()) }
		for i, part in pairs(parts) do
			page = page .. part
			coroutine.yield(part)
		end

		uwsgi.cache_set(env.REQUEST_URI, page)
	end

	if html then
		return nil,{}, coroutine.wrap(send_cache)
	end

	return nil,{}, coroutine.wrap(body)
end

return route
