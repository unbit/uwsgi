(ns myapp
 (import uwsgi)
)

(defn handler [req]
     {:status 200
      :headers { "Content-Type" "text/html" , "Server" "uWSGI" }
      :body (str "<h1>The requested uri is " (get req :uri) "</h1>" "<h2>reverse is " (uwsgi/rpc (into-array ["" "reverse" (get req :uri)])) "</h2>" )
     }
)
