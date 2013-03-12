(ns uwsgi.ring.tests.simple
  (:use [compojure.core]) )

(defn hello [] "Hello, World!")

(defn echo [msg] msg)

(defn palindrome [msg] (clojure.string/reverse msg) )

(defroutes app-routes
  (GET "/hello" [] (hello) )
  (GET "/echo" [msg] (echo msg) )
  (GET "/palindrome" [msg] (palindrome msg) )
)
