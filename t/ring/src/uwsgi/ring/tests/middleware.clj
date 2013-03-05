(ns uwsgi.ring.tests.middleware
  (:use [compojure.core]))

(defn hello-world [])

(defn echo [])

(defn palindrome [])

(defroutes app-routes
  (GET "/helloworld" [] hello-world)
  (GET "/echo" [] echo)
  (GET "/palindrome" [] palindrome))
