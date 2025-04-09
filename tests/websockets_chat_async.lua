#!./uwsgi --http :9090 --http-modifier1 6 --http-raw-body --async 256 --ugreen --master --lua tests/websockets_chat_async.lua

-- Same worker = Same luaState = Same chat room

local PAGE_STATIC = [[<html>
<head>
  <script language="Javascript">
    var s = new WebSocket("%s://%s/foobar/", ["chat","foo","bar"]);
    s.onopen = function() {
      alert("connected !!!");
      s.send("ciao");
    };
    s.onmessage = function(e) {
var bb = document.getElementById('blackboard')
var html = bb.innerHTML;
bb.innerHTML = html + '<br/>' + e.data;
    };

s.onerror = function(e) {
    alert(e);
}

s.onclose = function(e) {
alert("connection closed");
}

    function invia() {
      var value = document.getElementById('testo').value;
      s.send(value);
    }
  </script>
</head>
<body>
<h1>WebSocket</h1>
<input type="text" id="testo"/>
<input type="button" value="invia" onClick="invia();"/>
<div id="blackboard" style="width:640px;height:480px;background-color:black;color:white;border: solid 2px red;overflow:auto">
</div>
</body>
</html>
]];

local PAGE_STATIC_HEADERS = { ["Content-type"] = "text/html" };

local MSG_FORMAT = "[%s][%s]: %s";
local MSG_DATE_FORMAT = "%H:%M:%S";

local subs = {};

local send_to_subs = function(msg)
    uwsgi.log(msg);

    for id, handler in next, subs do
        if not handler:send(msg) then
            subs[id] = nil;
        end
    end
end

local say = function(who, msg)
    if msg:len() > 0 then
        send_to_subs(string.format(MSG_FORMAT, os.date(MSG_DATE_FORMAT), who or "System", msg));
    end
end

local loop = function(my_name)
    local wait_fd = uwsgi.connection_fd();

    while true do
        uwsgi.wait_fd_read(wait_fd, 30); -- 2th arg for ping/pong
        coroutine.yield();
        say(my_name, uwsgi.websocket_recv_nb());
    end
end

local gogo_websockets = function(env)

    uwsgi.websocket_handshake(nil, nil, "chat");

    local handler = assert(uwsgi.websocket_handler(), "no handler");
    local id = assert(handler:async_id(), "handler is dead");

    subs[id] = handler; -- add to subs

    local my_name = "User" .. id;

    say(nil, my_name .. " Has been Connected"); -- say hallo

    pcall(loop, my_name); -- start listen from user

    subs[id] = nil; -- remove from subs

    say(nil, my_name .. " Has been Disconnected"); -- say bye

end

return function(env)

    if env['PATH_INFO'] == '/' then
        return "200", PAGE_STATIC_HEADERS, string.format(PAGE_STATIC, env['HTTPS'] and 'wss' or 'ws', env['HTTP_HOST']);
    end

    if env['PATH_INFO'] == '/foobar/' then
        return nil, nil, coroutine.wrap(gogo_websockets), env;
    end

    return "404";
end
