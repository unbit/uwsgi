<%@ language="C#"%>

Hello 1<br/>
<%= System.Text.Encoding.UTF8.GetString(uwsgi.api.CacheGet("/etc/passwd")) %><br/>
Hello 1<br/>
