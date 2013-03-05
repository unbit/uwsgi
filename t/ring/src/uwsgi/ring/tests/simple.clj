(ns uwsgi.ring.tests.simple
  (:use [compojure.core]))

(defn hello-world [] "Hello, World!")

(defn echo [msg] msg)

(defn palindrome [msg] (clojure.string/reverse msg))

(defroutes app-routes
  (GET "/helloworld" [] (hello-world))
  (GET "/echo" [msg] (echo msg))
  (GET "/palindrome" [msg] (palindrome msg)))
