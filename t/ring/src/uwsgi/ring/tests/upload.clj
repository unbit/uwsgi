(ns uwsgi.ring.tests.upload
  (:use [compojure.core]))

(defn upload-file [fname fsize fbody] {
  :status 200
  :headers { "Content-Type" "text/html" , "Server" "uWSGI" }
  :body (str "<h1>Uploaded file</h1>"
           "<ul>"
             "<li>" fname "</li>"
             "<li>" fsize "</li>"
           "</ul>")})

(defroutes app-routes
 (POST "/upload" {params :params}
   (let [file (params :file)
         file-name (file :filename)
         file-size (file :size)
         file-body (file :tempfile)]
    (upload-file file-name file-size file-body))))

