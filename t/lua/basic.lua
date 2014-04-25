function hello(wsapi_env)
  local headers = { ["Content-type"] = "text/html", ["set-cookie"] = {"foo=bar", "bar=baz"} }
  local function hello_text()
    coroutine.yield("<html><body>")
    coroutine.yield("<p>Hello Wsapi!</p>")
    coroutine.yield("<p>PATH_INFO: " .. wsapi_env.PATH_INFO .. "</p>")
    coroutine.yield("<p>SCRIPT_NAME: " .. wsapi_env.SCRIPT_NAME .. "</p>")
    coroutine.yield("<p>QUERY_STRING: " .. wsapi_env.QUERY_STRING .. "</p>")
    coroutine.yield("</body></html>")
  end
  return 200, headers, coroutine.wrap(hello_text)
end
 
return hello
