require 'sinatra'
require 'socket'
require 'json'

module EmperorStats
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

    <div class="container">
      <hr/>
      <h1>Emperor: <%=@stats['emperor']%></h1>
      <hr/>

      <div class="row">
              <div class="span8">
                  <table class="table table-striped table-bordered">
                    <thead>
                      <tr>
                        <th>name</th><th>pid</th><th>first run</th>
                        <th>last respawn</th>
                        <th>last heartbeat</th>
                        <th>loyal</th>
                        <th>respawns</th>
			<% if @stats['emperor_tyrant'] == 1 %>
                        <th>uid</th>
                        <th>gid</th>
			<% end %>
                     </tr>
                    </thead>
          <% for vassal in @stats['vassals'] %>
			<tr>
				<td><%=vassal['id']%></td>
				<td><%=vassal['pid']%></td>
				<td><%=Time.at(vassal['first_run']).strftime("%d %b %Y %H:%M:%S")%></td>
				<td><%=Time.at(vassal['last_run']).strftime("%d %b %Y %H:%M:%S")%></td>
				<td><% if vassal['last_heartbeat'] > 0 %><%=Time.at(vassal['last_heartbeat']).strftime("%d %b %Y %H:%M:%S")%><% end %></td>
				<td><% if vassal['loyal'] > 0 %><%=Time.at(vassal['last_loyal']).strftime("%d %b %Y %H:%M:%S")%><% end %></td>
				<td><%=vassal['respawns']%></td>
				<% if @stats['emperor_tyrant'] == 1 %>
					<td><%=vassal['uid']%></td>
					<td><%=vassal['gid']%></td>
				<% end %>
			</tr>
          <% end %>
                  </table>
              </div>


		<div class="span4">
			<h3>blacklist</h3>
			<table class="table table-striped table-bordered">
				<thead>
					<tr><th>name</th><th>throttle</th></tr>
					<% for bli in @stats['blacklist'] %>
						<tr>
							<td><%=bli['id']%></td>
							<td><%=bli['throttle_level']%></td>
						</tr>
					<% end %>
				</thead>
			</table>
		</div>
      </div>



    <script src="https://unbit.github.com/jquery-1.7.2.min.js" type="text/javascript"></script>
    <script src="https://unbit.github.com/bootstrap/js/bootstrap.min.js" type="text/javascript"></script>
  </body>
</html>
eof

get '/' do
  @stats = EmperorStats::uwsgi_get_stats(ENV['EMPEROR']) 
  @title = 'uWSGI Emperor monitor'
  erb template
end

run Sinatra::Application
