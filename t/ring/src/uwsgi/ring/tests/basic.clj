(ns uwsgi.ring.tests.basic)

(defn index-page [req] {:status 200
  :headers { "Content-Type" "text/html" , "Server" "uWSGI" }
  :body (str "<h1>Ring test suites</h1>"
             "<h2>Simple tests</h2>"
             "<ul>"
               "<li><a href='/hello'>hello</a></li>"
               "<li><a href='/echo?msg=abc'>echo</a></li>"
               "<li><a href='/palindrome?msg=abc'>palindrome</a></li>"
             "</ul>"
             "<h2>Body type tests</h2>"
             "<ul>"
               "<li><a href='/sequence'>sequence</a></li>"
               "<li><a href='/file'>file</a></li>"
               "<li><a href='/stream'>stream</a></li>"
             "</ul>"
             "<h2>Upload tests</h2>"
             "<form action='/upload' enctype='multipart/form-data' method='post'>"
             "<p>"
                "Please select a file<br>"
                "<input type='file' name='file' size='40'>"
             "</p>"
             "<input type='submit' value='Upload'>"
             "</form>"
             "<h2>Other tests</h2>"
             "<ul>"
               "<li>...</li>"
             "</ul>")})

