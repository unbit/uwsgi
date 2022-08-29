require 'sinatra'
require 'socket'
require 'json'

module USubscribers
  def self.uwsgi_get_stats(server)
    parts = server.split(':')
      if parts.length > 1
        s = TCPSocket.open(parts[0], parts[1])
      else
        s = UNIXSocket.open(server)
      end
      return JSON.parse(s.read())
  end
end

template = <<eof
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title><%=@title%></title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="">
    <meta name="author" content="unbit">
    <link href="https://unbit.github.com/bootstrap/css/bootstrap.css" rel="stylesheet">
    <style>
      body {
        padding-top: 60px; /* 60px to make the container go all the way to the bottom of the topbar */
      }
    </style>
    <link href="https://unbit.github.com/bootstrap/css/bootstrap-responsive.css" rel="stylesheet">
  </head>
  <body>

    <div class="navbar navbar-fixed-top">
      <div class="navbar-inner">
        <div class="container">
          <a class="brand" href="#"><%=@title%></a>
        </div>
      </div>
    </div>

    <% for server in @servers.keys %>
    <div class="container">
      <hr/>
      <h1>SubscriptionServer: <%=server%></h1>
      <hr/>

      <div class="row">
          <% for pool in @servers[server] %>
              <div class="span6">
                  <h3><%=pool['key']%> (<%=pool['hits']%> hits)</h3>
                  <table class="table table-striped table-bordered">
                    <thead>
                      <tr>
                        <th>node</th><th>load</th><th>requests</th>
                        <th>last check</th>
                        <th>fail count</th>
                     </tr>
                    </thead>
                    <% for node in pool['nodes'] %>
                      <tr>
                        <td><%=node['name']%></td><td><%=node['load']%></td><td><%=node['requests']%></td>
                        <td><%=Time.at(node['last_check']).strftime("%d-%m-%Y %H:%M:%S")%></td>
                        <td><%=node['failcnt']%></td>
                      </tr>
                    <% end %>
                  </table>
              </div>
          <% end %>
      </div>

    </div> 

    <% end %>

    <script src="https://unbit.github.com/jquery-1.7.2.min.js" type="text/javascript"></script>
    <script src="https://unbit.github.com/bootstrap/js/bootstrap.min.js" type="text/javascript"></script>
  </body>
</html>
eof

get '/' do
  @servers = {}
  for server in ENV['U_SERVERS'].split(',')
    stats = USubscribers::uwsgi_get_stats(server) 
    if stats
      @servers[server] = stats['subscriptions']
    end
  end
  @title = 'uWSGI subscriptions viewer'
  erb template
end

run Sinatra::Application
