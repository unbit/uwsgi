#!./uwsgi --https :8443,foobar.crt,foobar.key --http-modifier1 6 --http-raw-body --threads 100 --lua tests/websockets_echo.lua

function app(env)
    local function html()
        coroutine.yield(string.format([[
    <html>
      <head>
          <script language="Javascript">
            var s = new WebSocket("%s://%s/foobar/", ["echo","foo","bar"]);
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
        ]], ws_scheme, env['HTTP_HOST']))
    end

    ws_scheme = 'ws'
    if env['HTTPS'] ~= nil then
        ws_scheme = 'wss'
    end
    
    if env['PATH_INFO'] == '/' then
        return 200, { ["Content-type"] = "text/html" }, coroutine.wrap(html)

    elseif env['PATH_INFO'] == '/foobar/' then
        uwsgi.websocket_handshake(nil, nil, 'echo')
        print("websockets...")
        while 1 do
            msg = uwsgi.websocket_recv()
            uwsgi.websocket_send(string.format("[%s] %s", os.time(), msg))
        end
    end
end

return app
