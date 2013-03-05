(ns uwsgi.ring.tests.app
  (:use compojure.core)
  (:use [ring.middleware params
                         keyword-params
                         nested-params])
  (:require [compojure.route :as route]
            [uwsgi.ring.tests.simple :as simple]
            [uwsgi.ring.tests.middleware :as middleware]
            [uwsgi.ring.tests.upload :as upload])
  (:gen-class
      :main true))

(defn app-routes [req]
  ((routes simple/app-routes middleware/app-routes upload/app-routes) req))

(def app
  (-> app-routes
      wrap-keyword-params
      wrap-nested-params
      wrap-params))

(defn -main [& args]
  (println "uwsgi ring tests app loaded"))

