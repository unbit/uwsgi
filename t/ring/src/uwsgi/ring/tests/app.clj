(ns uwsgi.ring.tests.app
  (:use compojure.core)
  (:use [ring.middleware params
                         keyword-params
                         nested-params
                         multipart-params])
  (:require [compojure.route :as route]
            [uwsgi.ring.tests.basic :as basic]
            [uwsgi.ring.tests.body :as body]
            [uwsgi.ring.tests.simple :as simple]
            [uwsgi.ring.tests.upload :as upload])
  (:gen-class
      :main true))

(defn app-routes [req]
  (if (= (get req :uri) "/")
    (basic/index-page req)
    ((routes simple/app-routes body/app-routes upload/app-routes (route/not-found "<h1>Page not found</h1>")) req)))

(def app
  (-> app-routes
      wrap-keyword-params
      wrap-nested-params
      wrap-params
      wrap-multipart-params))

(defn -main [& args]
  (println "uwsgi ring tests app loaded"))

